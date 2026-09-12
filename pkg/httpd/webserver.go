package httpd

import (
	"context"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LeeEirc/elfinder"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/jumpserver-dev/sdk-go/model"
	"github.com/jumpserver-dev/sdk-go/service"
	"github.com/jumpserver/koko/pkg/auth"
	"github.com/jumpserver/koko/pkg/common"
	"github.com/jumpserver/koko/pkg/config"
	"github.com/jumpserver/koko/pkg/httpd/ws"
	"github.com/jumpserver/koko/pkg/logger"
)

const (
	defaultBufferSize = 1024
	WebsocketErrorf   = "Websocket upgrade err: %s"
)

var upGrader = websocket.Upgrader{
	ReadBufferSize:  defaultBufferSize,
	WriteBufferSize: defaultBufferSize,
	Subprotocols:    []string{"JMS-KOKO"},
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func NewServer(jmsService *service.JMService) *Server {
	srv := &Server{broadCaster: NewBroadcaster(), apiClient: jmsService}
	eng := createRouter(jmsService, srv)
	conf := config.GetConf()
	addr := net.JoinHostPort(conf.BindHost, conf.HTTPPort)
	srv.Srv = &http.Server{Addr: addr, Handler: eng}
	return srv
}

type Server struct {
	broadCaster *broadcaster
	Srv         *http.Server
	apiClient   *service.JMService

	// SIGTERM 排水状态: 排水中拒绝新的 ws 连接并等存量结束。
	// listener 刻意保持打开 —— /koko/health/ 继续返回 200, 避免排水中途
	// liveness 探针失败被 kubelet 掐死(k8s 在 Pod 删除时本就会把它从
	// EndpointSlice 摘除, 不依赖这里关 listener 断新流量)
	draining int32
	wsConns  int32
}

func (s *Server) Start() {
	go s.broadCaster.Start()
	logger.Info("Start HTTP Server at ", s.Srv.Addr)
	log.Print(s.Srv.ListenAndServe())
}

// DrainGuard 挂在 /koko/ws/ 路由组: 排水中拒新连接(503), 平时对活跃
// websocket 连接计数, 供 Stop() 等待
func (s *Server) DrainGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if atomic.LoadInt32(&s.draining) == 1 {
			c.String(http.StatusServiceUnavailable, "koko is draining")
			c.Abort()
			return
		}
		atomic.AddInt32(&s.wsConns, 1)
		defer atomic.AddInt32(&s.wsConns, -1)
		c.Next()
	}
}

func (s *Server) Stop() {
	drainTimeout := config.GetConf().SSHDrainTimeout
	if drainTimeout > 0 {
		// 排水模式: 拒新 ws → 等存量 ws 全部断开或超时 → 最后才关 listener。
		// 每 2s 轮询计数, 每 10s 打印剩余(与 sshd 的 drainReportInterval 对齐)
		atomic.StoreInt32(&s.draining, 1)
		logger.Infof(
			"HTTP server draining, waiting up to %d seconds for websocket connections, %d active",
			drainTimeout, atomic.LoadInt32(&s.wsConns))
		deadline := time.Now().Add(time.Duration(drainTimeout) * time.Second)
		waited := 0
		for atomic.LoadInt32(&s.wsConns) > 0 && time.Now().Before(deadline) {
			time.Sleep(2 * time.Second)
			waited += 2
			if waited%10 == 0 {
				logger.Infof("HTTP server draining: %d websocket connections remaining",
					atomic.LoadInt32(&s.wsConns))
			}
		}
		if n := atomic.LoadInt32(&s.wsConns); n > 0 {
			logger.Errorf(
				"HTTP server drain timeout after %d seconds, %d websocket connections will be closed",
				drainTimeout, n)
		} else {
			logger.Infof("HTTP server drained, all websocket connections finished")
		}
		ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelFunc()
		_ = s.Srv.Shutdown(ctx)
		return
	}
	ctx, cancelFunc := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancelFunc()
	if s.Srv != nil {
		_ = s.Srv.Shutdown(ctx)
	}
}

func (s *Server) SftpHostConnectorView(ctx *gin.Context) {
	var params struct {
		Sid string `form:"sid"`
	}
	switch ctx.Request.Method {
	case http.MethodGet, http.MethodPost:
		if err := ctx.ShouldBind(&params); err != nil {
			logger.Errorf("Invalid elfinder request url %s from ip %s",
				ctx.Request.URL, ctx.ClientIP())
			ctx.String(http.StatusBadRequest, "invalid elfinder request")
			return
		}
	default:
		ctx.AbortWithStatus(http.StatusMethodNotAllowed)
		return
	}
	var userV *UserVolume
	if wsCon := s.broadCaster.GetUserWebsocket(params.Sid); wsCon != nil {
		handler := wsCon.GetHandler()
		switch handler.Name() {
		case WebFolderName:
			userV = handler.(*webFolder).GetVolume()
		}
	}
	if userV == nil {
		logger.Errorf("Ws(%s) already closed request url %s from ip %s",
			params.Sid, ctx.Request.URL, ctx.ClientIP())
		ctx.String(http.StatusBadRequest, "ws already disconnected")
		return
	}
	logger.Infof("Elfinder ws %s connected again.", params.Sid)
	conf := config.GetConf()
	maxSize := common.ConvertSizeToBytes(conf.ZipMaxSize)
	options := map[string]string{
		"ZipMaxSize": strconv.Itoa(maxSize),
		"ZipTmpPath": conf.ZipTmpPath,
	}
	conn := elfinder.NewElFinderConnectorWithOption([]elfinder.Volume{userV}, options)
	conn.ServeHTTP(ctx.Writer, ctx.Request)
}

func (s *Server) ProcessTerminalWebsocket(ctx *gin.Context) {
	userConn, err := s.UpgradeUserWsConn(ctx)
	if err != nil {
		logger.Errorf(WebsocketErrorf, err)
		return
	}
	s.runTTY(userConn)
}

func (s *Server) ProcessElfinderWebsocket(ctx *gin.Context) {
	userConn, err := s.UpgradeUserWsConn(ctx)
	if err != nil {
		logger.Errorf(WebsocketErrorf, err)
		return
	}
	userConn.handler = &webFolder{
		ws:   userConn,
		done: make(chan struct{}),
	}
	s.broadCaster.EnterUserWebsocket(userConn)
	defer s.broadCaster.LeaveUserWebsocket(userConn)
	userConn.Run()
}

func (s *Server) ProcessSftpWebsocket(ctx *gin.Context) {
	userConn, err := s.UpgradeUserWsConn(ctx)
	if err != nil {
		logger.Errorf(WebsocketErrorf, err)
		return
	}
	userConn.handler = &webSftp{
		ws:   userConn,
		done: make(chan struct{}),
	}
	s.broadCaster.EnterUserWebsocket(userConn)
	defer s.broadCaster.LeaveUserWebsocket(userConn)
	userConn.Run()
}

func (s *Server) ChatAIWebsocket(ctx *gin.Context) {
	userConn, err := s.UpgradeUserWsConn(ctx)
	if err != nil {
		logger.Errorf(WebsocketErrorf, err)
		return
	}

	termConf, err := userConn.apiClient.GetTerminalConfig()
	if err != nil {
		logger.Errorf("Get terminal config failed: %s", err)
		return
	}

	userConn.handler = &chat{
		ws:            userConn,
		conversations: sync.Map{},
		term:          &termConf,
	}
	s.broadCaster.EnterUserWebsocket(userConn)
	defer s.broadCaster.LeaveUserWebsocket(userConn)
	userConn.Run()
}

func (s *Server) UpgradeUserWsConn(ctx *gin.Context) (*UserWebsocket, error) {
	underWsCon, err := upGrader.Upgrade(ctx.Writer, ctx.Request, ctx.Writer.Header())
	if err != nil {
		return nil, err
	}
	wsSocket := ws.NewSocket(underWsCon, ctx.Request)

	apiClient := s.apiClient.Copy()
	langCode := config.GetConf().LanguageCode
	if acceptLang := ctx.GetHeader("Accept-Language"); acceptLang != "" {
		apiClient.SetHeader("Accept-Language", acceptLang)
		langCode = ParseAcceptLanguageCode(acceptLang)
	}
	if cookieLang, err2 := ctx.Cookie("django_language"); err2 == nil {
		apiClient.SetCookie("django_language", cookieLang)
		langCode = cookieLang
	}

	//设置 websocket 协议层面对应的ping和pong 处理方法
	underWsCon.SetPingHandler(func(appData string) error {
		logger.Debugf("Websocket ping %s", appData)
		return wsSocket.WritePong([]byte(appData), maxWriteTimeOut)
	})
	underWsCon.SetPongHandler(func(appData string) error {
		logger.Debugf("Websocket pong %s", appData)
		return wsSocket.WritePing([]byte(appData), maxWriteTimeOut)
	})

	userValue := ctx.MustGet(auth.ContextKeyUser)
	currentUser := userValue.(*model.User)
	setting := s.getPublicSetting()
	userConn := &UserWebsocket{
		Uuid:           common.UUID(),
		conn:           wsSocket,
		ctx:            ctx.Copy(),
		messageChannel: make(chan *Message, 10),
		user:           currentUser,
		setting:        &setting,
		apiClient:      apiClient,
		langCode:       langCode,
	}
	return userConn, nil
}

func (s *Server) runTTY(userConn *UserWebsocket) {
	ttyHandler := &tty{
		ws: userConn,
	}
	userConn.handler = ttyHandler
	s.broadCaster.EnterUserWebsocket(userConn)
	defer s.broadCaster.LeaveUserWebsocket(userConn)
	userConn.Run()
}

var upTime = time.Now()

func (s *Server) HealthStatusHandler(ctx *gin.Context) {
	status := make(map[string]interface{})
	now := time.Now()
	status["timestamp"] = now.UTC()
	status["uptime"] = now.Sub(upTime).String()
	ctx.JSON(http.StatusOK, status)
}

func (s *Server) GenerateViewMeta(targetId string) (meta ViewPageMata) {
	meta.ID = targetId
	setting, err := s.apiClient.GetPublicSetting()
	if err != nil {
		logger.Errorf("Get core api public setting err: %s", err)
	}
	meta.IconURL = setting.Interface.Favicon
	return
}

func (s *Server) getPublicSetting() model.PublicSetting {
	setting, err := s.apiClient.GetPublicSetting()
	if err != nil {
		logger.Errorf("Get Public setting err: %s", err)
	}
	return setting
}

func ParseAcceptLanguageCode(language string) string {
	// en,zh-TW;q=0.9,zh-CN;q=0.8,zh;q=0.7
	// 解析出第一个语言代码
	if language == "" {
		return "zh-CN"
	}
	languages := strings.SplitN(language, ";", 2)
	lang := strings.TrimSpace(languages[0])
	languages = strings.SplitN(lang, ",", 2)
	return languages[0]
}
