package handler

import (
	"testing"

	"github.com/jumpserver-dev/sdk-go/model"
)

func TestIsForbiddenPortForwarding(t *testing.T) {
	token := &model.ConnectToken{Asset: model.Asset{Protocols: []model.Protocol{
		{Name: model.ProtocolSSH, Port: 2222},
		{Name: "http", Port: 8080},
	}}}
	tests := []struct {
		address string
		blocked bool
	}{
		{"127.0.0.1:2222", true},
		{"127.0.0.1:8080", false},
		{"[::1]:2222", true},
		{"invalid", false},
	}
	for _, test := range tests {
		blocked, _ := isForbiddenPortForwarding(test.address, token)
		if blocked != test.blocked {
			t.Errorf("forwarding %s blocked=%t, want %t", test.address, blocked, test.blocked)
		}
	}
}
