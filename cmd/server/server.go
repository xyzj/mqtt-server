package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"strconv"
	"sync/atomic"

	"github.com/xyzj/mqtt-server"
	"github.com/xyzj/mqtt-server/hooks/auth"
	"github.com/xyzj/mqtt-server/listeners"
	"github.com/xyzj/toolbox/crypto"
)

// Opt server option
type Opt struct {
	// TLSConfig tls config，when set, ignore Cert, Key and RootCA
	TLSConfig *tls.Config
	// AuthConfig auth config，when set, ignore Authfile
	AuthConfig *auth.Ledger
	// 文件日志写入器
	FileLogger *slog.Logger
	// tls cert file path
	Cert string
	// tls key file path
	Key string
	// tls root ca file path
	RootCA string
	// mqtt port
	PortMqtt int
	// mqtt+tls port
	PortTLS int
	// http status port
	PortWeb int
	// websocket port
	PortWS int
	// max message expiry time in seconds
	MaxMsgExpirySeconds int
	// max session expiry time in seconds
	MaxSessionExpirySeconds int
	// clients read and write buffer size in bytes
	ClientsBufferSize int
	// DisableAuth clients do not need username and password
	DisableAuth bool
	// InsideJob enable or disable inline client
	InsideJob bool
}

func (o *Opt) ensureDefaults() {
	if o.MaxMsgExpirySeconds == 0 {
		o.MaxMsgExpirySeconds = 60 * 60
	}
	if o.MaxSessionExpirySeconds == 0 {
		o.MaxSessionExpirySeconds = 60 * 6
	}
	if o.ClientsBufferSize < 8192 {
		o.ClientsBufferSize = 8192
	}
	if o.PortMqtt >= 65535 {
		o.PortMqtt = 0
	}
	if o.PortTLS >= 65535 {
		o.PortTLS = 0
	}
	if o.PortWS >= 65535 {
		o.PortWS = 0
	}
	if o.PortWeb >= 65535 {
		o.PortWeb = 0
	}
	if o.AuthConfig == nil {
		o.DisableAuth = true
		o.AuthConfig = new(auth.Ledger)
	}
}

// MqttServer a new mqtt server
type MqttServer struct {
	svr *mqtt.Server
	opt *Opt
	st  *atomic.Bool
}

// NewServer make a new server
func NewServer(opt *Opt) *MqttServer {
	opt.ensureDefaults()
	// a new svr
	cap := mqtt.NewDefaultServerCapabilities()
	cap.MaximumMessageExpiryInterval = int64(opt.MaxMsgExpirySeconds)
	cap.MaximumSessionExpiryInterval = uint32(opt.MaxSessionExpirySeconds)
	mopt := &mqtt.Options{
		InlineClient:             opt.InsideJob,
		ClientNetWriteBufferSize: opt.ClientsBufferSize,
		ClientNetReadBufferSize:  opt.ClientsBufferSize,
		Capabilities:             cap,
		Logger:                   opt.FileLogger,
	}

	svr := mqtt.New(mopt)
	return &MqttServer{
		svr: svr,
		opt: opt,
		st:  &atomic.Bool{},
	}
}

// Stop close server
func (m *MqttServer) Stop() {
	if m == nil || m.svr == nil {
		return
	}
	m.svr.Close()
	m.st.Store(false)
}

// Run start server and wait
func (m *MqttServer) Run() {
	if m.Start() == nil {
		m.st.Store(true)
		select {}
	}
	m.st.Store(false)
}

// IsRunning check the server status
func (m *MqttServer) IsRunning() bool {
	return m.st.Load()
}

// Start start server
func (m *MqttServer) Start() error {
	if m == nil || m.svr == nil {
		return fmt.Errorf("use NewServer() to create a new mqtt server")
	}
	var err error
	// set auth
	if m.opt.DisableAuth {
		err = m.svr.AddHook(&auth.AllowHook{}, nil)
	} else {
		err = m.svr.AddHook(&auth.Hook{}, &auth.Options{
			Ledger: m.opt.AuthConfig,
		})
	}
	if err != nil {
		m.svr.Log.Error("config auth error: " + err.Error())
		return err
	}
	// check tls files
	var tl *tls.Config
	if m.opt.TLSConfig != nil {
		tl = m.opt.TLSConfig
	} else {
		tl, err = crypto.TLSConfigFromFile(m.opt.Cert, m.opt.Key, m.opt.RootCA)
		if err != nil {
			m.opt.PortTLS = 0
			m.svr.Log.Warn(err.Error())
		}
	}
	// mqtt tls service
	if m.opt.PortTLS > 0 {
		err = m.svr.AddListener(listeners.NewTCP(listeners.Config{
			ID:        "mqtt+tls",
			Address:   ":" + strconv.Itoa(m.opt.PortTLS),
			TLSConfig: tl,
		}))
		if err != nil {
			m.svr.Log.Error("MQTT+TLS service error: " + err.Error())
			return err
		}
	}
	// mqtt service
	if m.opt.PortMqtt > 0 {
		err = m.svr.AddListener(listeners.NewTCP(listeners.Config{
			ID:        "mqtt",
			Address:   ":" + strconv.Itoa(m.opt.PortMqtt),
			TLSConfig: nil,
		}))
		if err != nil {
			m.svr.Log.Error("MQTT service error: " + err.Error())
			return err
		}
	}
	// websocket service
	if m.opt.PortWS > 0 {
		err = m.svr.AddListener(listeners.NewWebsocket(listeners.Config{
			ID:        "ws",
			Address:   ":" + strconv.Itoa(m.opt.PortWS),
			TLSConfig: tl,
		}))
		if err != nil {
			m.svr.Log.Error("WS service error: " + err.Error())
			return err
		}
	}
	// http status service
	if m.opt.PortWeb > 0 {
		userMap := make(map[string]string)
		if !m.opt.DisableAuth {
			for name, v := range m.opt.AuthConfig.Users {
				if name != "" && string(v.Password) != "" {
					userMap[name] = string(v.Password)
				}
			}
			for _, v := range m.opt.AuthConfig.Auth {
				if string(v.Username) != "" && string(v.Password) != "" {
					userMap[string(v.Username)] = string(v.Password)
				}
			}
		}
		err = m.svr.AddListener(NewHTTPStats(&listeners.Config{
			ID:      "web",
			Address: ":" + strconv.Itoa(m.opt.PortWeb),
		},
			m.svr.Info,
			m.svr.Clients,
			&Lopt{
				PortMqtt: m.opt.PortMqtt,
				PortTLS:  m.opt.PortTLS,
				PortWS:   m.opt.PortWS,
				Auth:     userMap,
			},
		))
		if err != nil {
			m.svr.Log.Error("HTTP service error: " + err.Error())
			return err
		}
	}
	// start serve
	err = m.svr.Serve()
	if err != nil {
		m.svr.Log.Error("serve error: " + err.Error())
		return err
	}
	return nil
}

// Subscribe use inline client to receive message
func (m *MqttServer) Subscribe(filter string, subscriptionId int, handler mqtt.InlineSubFn) error {
	return m.svr.Subscribe(filter, subscriptionId, handler)
}

// Publish use inline client publish a message,retain==false
func (m *MqttServer) Publish(topic string, payload []byte, qos byte) error {
	return m.svr.Publish(topic, payload, false, qos)
}
