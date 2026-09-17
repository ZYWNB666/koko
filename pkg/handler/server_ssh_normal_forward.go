package handler

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/gliderlabs/ssh"
	"github.com/jumpserver-dev/sdk-go/common"
	"github.com/jumpserver-dev/sdk-go/model"
	"github.com/jumpserver/koko/pkg/auth"
	"github.com/jumpserver/koko/pkg/logger"
	"github.com/jumpserver/koko/pkg/session"
	"github.com/jumpserver/koko/pkg/srvconn"
	gossh "golang.org/x/crypto/ssh"
)

func releaseForwardSSHClient(client *srvconn.SSHClient) {
	if client.KeyId != "" {
		srvconn.ReleaseClientCacheKey(client.KeyId, client)
	} else {
		_ = client.Close()
	}
}

// handleNormalPortForwarding 处理普通的 SSH 端口转发（非 VSCode 场景）
func (s *Server) handleNormalPortForwarding(ctx ssh.Context, newChan gossh.NewChannel, destAddr string) {
	user, ok := ctx.Value(auth.ContextKeyUser).(*model.User)
	if !ok {
		logger.Errorf("handleNormalPortForwarding: cannot get user from context")
		_ = newChan.Reject(gossh.Prohibited, "authentication failed")
		return
	}

	// 获取直接登录请求信息
	directReq := ctx.Value(auth.ContextKeyDirectLoginFormat)
	directRequest, ok := directReq.(*auth.DirectLoginAssetReq)
	if !ok {
		logger.Errorf("handleNormalPortForwarding: not a direct login request")
		_ = newChan.Reject(gossh.Prohibited, "port forwarding requires direct asset login")
		return
	}

	// 获取 token 信息
	var tokenInfo *model.ConnectToken
	if directRequest.IsToken() {
		// 已经有 token 信息，直接使用
		tokenInfo = directRequest.ConnectToken
	} else {
		// 需要构建 token
		var err error
		tokenInfo, err = s.buildConnectToken(ctx, user, directRequest)
		if err != nil {
			logger.Errorf("handleNormalPortForwarding: cannot build connect token: %s", err)
			_ = newChan.Reject(gossh.Prohibited, "cannot build connection token")
			return
		}
	}
	if tokenInfo == nil {
		_ = newChan.Reject(gossh.Prohibited, "missing connection token")
		return
	}

	// 验证协议和资产支持
	matchedProtocol := tokenInfo.Protocol == model.ProtocolSSH
	assetSupportedSSH := tokenInfo.Asset.IsSupportProtocol(model.ProtocolSSH)
	if !matchedProtocol || !assetSupportedSSH {
		logger.Errorf("handleNormalPortForwarding: not ssh asset connection token")
		_ = newChan.Reject(gossh.Prohibited, "only SSH protocol supported for port forwarding")
		return
	}

	// 检查目标端口是否禁止转发（基于资产配置的实际端口）
	if forbidden, protocol := isForbiddenPortForwarding(destAddr, tokenInfo); forbidden {
		logger.Errorf("handleNormalPortForwarding: forbidden port forwarding to %s (%s protocol)", destAddr, protocol)
		_ = newChan.Reject(gossh.Prohibited, fmt.Sprintf("port forwarding to %s is forbidden for security reasons", protocol))
		return
	}

	// 创建 SSH 客户端连接
	sshClient, err := s.buildSSHClient(tokenInfo)
	if err != nil {
		logger.Errorf("handleNormalPortForwarding: build ssh client failed: %s", err)
		_ = newChan.Reject(gossh.ConnectionFailed, "cannot connect to target asset")
		return
	}

	// 创建审计会话
	host, _, _ := net.SplitHostPort(ctx.RemoteAddr().String())
	reqSession := tokenInfo.CreateSession(host, model.LoginFromSSH, model.TUNNELType)
	respSession, err := s.jmsService.CreateSession(reqSession)
	if err != nil {
		logger.Errorf("handleNormalPortForwarding: create session failed: %s", err)
		releaseForwardSSHClient(sshClient)
		_ = newChan.Reject(gossh.ConnectionFailed, "cannot create audit session")
		return
	}

	// 设置上下文取消
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 创建会话追踪
	respSession.TokenId = tokenInfo.Id
	traceSession := session.NewSession(&respSession, func(task *model.TerminalTask) error {
		switch task.Name {
		case model.TaskKillSession:
			cancel()
			logger.Infof("User %s port forwarding session terminated by admin", user.String())
			return nil
		case model.TaskPermExpired:
			cancel()
			logger.Infof("User %s port forwarding session expired", user.String())
			return nil
		case model.TaskPermValid:
			return nil
		}
		return fmt.Errorf("port forwarding not support task: %s", task.Name)
	})
	session.AddSession(traceSession)

	// 清理资源
	defer func() {
		if _, err2 := s.jmsService.SessionFinished(respSession.ID, common.NewNowUTCTime()); err2 != nil {
			logger.Errorf("Finish port forwarding session err: %s", err2)
		}
		session.RemoveSession(traceSession)
		releaseForwardSSHClient(sshClient)
	}()

	// 记录会话生命周期
	s.recordSessionLifecycle(respSession.ID, model.AssetConnectSuccess, "")
	defer s.recordSessionLifecycle(respSession.ID, model.AssetConnectFinished, "")

	// 通过 SSH 客户端连接到目标地址
	dConn, err := sshClient.Dial("tcp", destAddr)
	if err != nil {
		logger.Errorf("handleNormalPortForwarding: dial to %s failed: %s", destAddr, err)
		_ = newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}
	defer dConn.Close()

	// 接受通道
	ch, reqs, err := newChan.Accept()
	if err != nil {
		logger.Errorf("handleNormalPortForwarding: accept channel failed: %s", err)
		return
	}
	defer ch.Close()

	logger.Infof("User %s start port forwarding to %s via asset %s (session: %s)",
		user.String(), destAddr, tokenInfo.Asset.String(), respSession.ID)
	go gossh.DiscardRequests(reqs)

	// 双向数据转发，监听上下文取消
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		defer ch.Close()
		defer dConn.Close()
		_, _ = io.Copy(ch, dConn)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		defer ch.Close()
		defer dConn.Close()
		_, _ = io.Copy(dConn, ch)
	}()

	// 等待转发完成或上下文取消
	completed := 0
	select {
	case <-done:
		completed++
		logger.Infof("User %s port forwarding completed", user.String())
	case <-childCtx.Done():
		logger.Infof("User %s port forwarding cancelled by context", user.String())
	}
	_ = ch.Close()
	_ = dConn.Close()
	for completed < 2 {
		<-done
		completed++
	}

	logger.Infof("User %s end port forwarding to %s (session: %s)", user.String(), destAddr, respSession.ID)
}
