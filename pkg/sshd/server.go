package sshd

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/pires/go-proxyproto"
	gossh "golang.org/x/crypto/ssh"

	"github.com/jumpserver-dev/sdk-go/service"
	"github.com/jumpserver/koko/pkg/config"
	"github.com/jumpserver/koko/pkg/handler"
	"github.com/jumpserver/koko/pkg/logger"
)

const (
	sshChannelSession     = "session"
	sshChannelDirectTCPIP = "direct-tcpip"
	sshSubSystemSFTP      = "sftp"

	ChannelTCPIPForward       = "tcpip-forward"
	ChannelCancelTCPIPForward = "cancel-tcpip-forward"
	ChannelForwardedTCPIP     = "forwarded-tcpip"

	// 排水期间打印剩余连接数的间隔
	drainReportInterval = 10 * time.Second
)

var (
	supportedMACs = []string{"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-256", "hmac-sha1"}

	supportedKexAlgos = []string{
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
	}
)

type Server struct {
	Srv     *ssh.Server
	Handler *handler.Server
	// 活跃 SSH 连接数(含菜单态/认证中的), gliderlabs Shutdown 等的就是
	// 这个数归零, 排水日志按它展示排空进度
	connCount int32
}

// countingListener: listener 层连接计数, 供排水期间打印剩余连接数
type countingListener struct {
	net.Listener
	connCount *int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	atomic.AddInt32(l.connCount, 1)
	return &countConn{Conn: conn, connCount: l.connCount}, nil
}

type countConn struct {
	net.Conn
	once      sync.Once
	connCount *int32
}

func (c *countConn) Close() error {
	c.once.Do(func() { atomic.AddInt32(c.connCount, -1) })
	return c.Conn.Close()
}

func (s *Server) Start() {
	logger.Infof("Start SSH server at %s", s.Srv.Addr)
	ln, err := net.Listen("tcp", s.Srv.Addr)
	if err != nil {
		logger.Fatal(err)
	}
	proxyListener := &proxyproto.Listener{Listener: ln}
	// !!! 不能像以前那样 logger.Fatal(Serve(...)): 排水时 Stop() 会先关
	// listener 拒新连接, Serve 返回 ErrServerClosed 属预期返回; 若在这里
	// Fatal 会当场退出进程, 排水等待(等存量会话结束)全部作废
	if err := s.Srv.Serve(&countingListener{
		Listener: proxyListener, connCount: &s.connCount,
	}); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
		logger.Fatal(err)
	}
}

func (s *Server) Stop() {
	drainTimeout := config.GetConf().SSHDrainTimeout
	if drainTimeout > 0 {
		// 排水模式: Shutdown 先关闭 listener(新连接立即被拒), 再等存量
		// 连接(含资产选择菜单里的)全部自然结束; 超时返回后由进程退出
		// 强制关闭剩余连接。期间每 10s 打印剩余连接数, 便于观察排空进度
		ctx, cancelFunc := context.WithTimeout(
			context.Background(), time.Duration(drainTimeout)*time.Second)
		defer cancelFunc()
		logger.Infof(
			"SSH server draining, waiting up to %d seconds for connections to finish, %d active",
			drainTimeout, atomic.LoadInt32(&s.connCount))
		stopTicker := make(chan struct{})
		go func() {
			ticker := time.NewTicker(drainReportInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					logger.Infof("SSH server draining: %d connections remaining",
						atomic.LoadInt32(&s.connCount))
				case <-stopTicker:
					return
				}
			}
		}()
		err := s.Srv.Shutdown(ctx)
		close(stopTicker)
		if err != nil {
			logger.Errorf(
				"SSH server drain timeout after %d seconds, %d connections will be closed",
				drainTimeout, atomic.LoadInt32(&s.connCount))
			return
		}
		logger.Infof("SSH server drained, all connections finished")
		return
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()
	logger.Fatal(s.Srv.Shutdown(ctx))
}

func NewSSHServer(jmsService *service.JMService) *Server {
	cf := config.GlobalConfig
	addr := net.JoinHostPort(cf.BindHost, cf.SSHPort)
	termCfg, err := jmsService.GetTerminalConfig()
	if err != nil {
		logger.Fatal(err)
	}
	singer, err := ParsePrivateKeyFromString(termCfg.HostKey)
	if err != nil {
		logger.Fatalf("Parse Terminal private key failed: %s\n", err)
	}
	sshHandler := handler.NewServer(termCfg, jmsService)
	srv := &ssh.Server{
		Addr:             addr,
		PasswordHandler:  sshHandler.PasswordAuth,
		PublicKeyHandler: sshHandler.PublicKeyAuth,
		Version:          "JumpServer",
		HostSigners:      []ssh.Signer{singer},
		MaxSessions:      int32(cf.SshMaxSessions),
		ServerConfigCallback: func(ctx ssh.Context) *gossh.ServerConfig {
			cfg := gossh.Config{MACs: supportedMACs, KeyExchanges: supportedKexAlgos}
			return &gossh.ServerConfig{Config: cfg}
		},
		Handler:                       sshHandler.SessionHandler,
		LocalPortForwardingCallback:   sshHandler.LocalPortForwardingPermission,
		ReversePortForwardingCallback: sshHandler.ReversePortForwardingPermission,
		SubsystemHandlers:             map[string]ssh.SubsystemHandler{sshSubSystemSFTP: sshHandler.SFTPHandler},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			sshChannelSession: ssh.DefaultSessionHandler,
			sshChannelDirectTCPIP: func(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
				localD := localForwardChannelData{}
				if err := gossh.Unmarshal(newChan.ExtraData(), &localD); err != nil {
					_ = newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
					return
				}

				if srv.LocalPortForwardingCallback == nil || !srv.LocalPortForwardingCallback(ctx, localD.DestAddr, localD.DestPort) {
					_ = newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
					return
				}
				dest := net.JoinHostPort(localD.DestAddr, strconv.FormatInt(int64(localD.DestPort), 10))
				sshHandler.DirectTCPIPChannelHandler(ctx, newChan, dest)
			},
		},
		RequestHandlers: map[string]ssh.RequestHandler{
			ChannelTCPIPForward:       sshHandler.HandleSSHRequest,
			ChannelCancelTCPIPForward: sshHandler.HandleSSHRequest,
		},
	}
	return &Server{Srv: srv, Handler: sshHandler}
}

type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}
