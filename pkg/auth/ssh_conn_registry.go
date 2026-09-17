package auth

import (
	"sync"
	"time"

	"github.com/gliderlabs/ssh"

	"github.com/jumpserver-dev/sdk-go/model"
)

// SSHConnInfo: 一条已完成认证的 SSH 连接的身份信息, 排水期间逐条打印,
// 用于回答"还挂着的连接是谁的"
type SSHConnInfo struct {
	SessionID string
	User      string // 显示名, model.User.String() = 姓名(用户名)
	RemoteIP  string
	LoginAt   time.Time
}

var sshConnRegistry = &connRegistry{conns: make(map[string]SSHConnInfo)}

type connRegistry struct {
	mu    sync.RWMutex
	conns map[string]SSHConnInfo
}

// RegisterSSHConn 认证成功时登记; ssh.Context 在连接断开时 Done, 自动注销。
// 同一连接多轮认证(强制双因素)重复登记时覆盖, 无副作用
func RegisterSSHConn(ctx ssh.Context, user *model.User, remoteAddr string) {
	info := SSHConnInfo{
		SessionID: ctx.SessionID(),
		RemoteIP:  remoteAddr,
		LoginAt:   time.Now(),
	}
	if user != nil {
		info.User = user.String()
	}
	sshConnRegistry.mu.Lock()
	sshConnRegistry.conns[info.SessionID] = info
	sshConnRegistry.mu.Unlock()
	go func() {
		<-ctx.Done()
		sshConnRegistry.mu.Lock()
		delete(sshConnRegistry.conns, info.SessionID)
		sshConnRegistry.mu.Unlock()
	}()
}

// ActiveSSHConns 返回当前已认证在线连接的快照(仅认证完成的;
// 认证中/认证失败的连接不在其中, 但会被 listener 计数覆盖到)
func ActiveSSHConns() []SSHConnInfo {
	sshConnRegistry.mu.RLock()
	defer sshConnRegistry.mu.RUnlock()
	infos := make([]SSHConnInfo, 0, len(sshConnRegistry.conns))
	for _, info := range sshConnRegistry.conns {
		infos = append(infos, info)
	}
	return infos
}
