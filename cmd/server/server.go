package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/xyzj/mqtt-server"
	"github.com/xyzj/mqtt-server/hooks/auth"
	"github.com/xyzj/mqtt-server/listeners"
	"github.com/xyzj/toolbox"
	"github.com/xyzj/toolbox/crypto"
	"github.com/xyzj/toolbox/logger"
)

// Opt server option
type Opt struct {
	// TLSConfig tls config，when set, ignore Cert, Key and RootCA
	TLSConfig *tls.Config
	// AuthConfig auth config，when set, ignore Authfile
	AuthConfig *auth.Ledger
	// 文件日志写入器
	FileLogger logger.Logger
	// tls cert file path
	Cert string
	// tls key file path
	Key string
	// tls root ca file path
	RootCA string
	// mqtt port
	MqttAddr string
	// mqtt+tls port
	MqttTlsAddr string
	// http status port
	WebAddr string
	// websocket port
	WSAddr string
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
	if o.ClientsBufferSize == 0 {
		o.ClientsBufferSize = 4096
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

	hopt := &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == "time" {
				return slog.Attr{}
			}
			return a
		},
		Level: slog.LevelInfo,
	}
	// a new svr
	cap := mqtt.NewDefaultServerCapabilities()
	cap.MaximumMessageExpiryInterval = int64(opt.MaxMsgExpirySeconds)
	cap.MaximumSessionExpiryInterval = uint32(opt.MaxSessionExpirySeconds)
	mopt := &mqtt.Options{
		InlineClient:             opt.InsideJob,
		ClientNetWriteBufferSize: opt.ClientsBufferSize,
		ClientNetReadBufferSize:  opt.ClientsBufferSize,
		Capabilities:             cap,
		Logger: slog.New(slog.NewTextHandler(
			opt.FileLogger.DefaultWriter(),
			hopt,
		)),
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
func (m *MqttServer) Run() error {
	err := m.Start()
	if err == nil {
		m.st.Store(true)
		select {}
	}
	m.st.Store(false)
	return err
}

// IsRunning check the server status
func (m *MqttServer) IsRunning() bool {
	return m.st.Load()
}

// Start start server
func (m *MqttServer) Start() error {
	if m == nil || m.svr == nil {
		return fmt.Errorf("[mqtt-broker] use NewServer() to create a new mqtt server")
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
		m.opt.FileLogger.Error("[mqtt-broker] config auth error: " + err.Error())
		return err
	}
	// check tls files
	var tl *tls.Config
	if m.opt.TLSConfig != nil {
		tl = m.opt.TLSConfig
	} else {
		tl, err = crypto.TLSConfigFromFile(m.opt.Cert, m.opt.Key, m.opt.RootCA)
		if err != nil {
			m.opt.MqttTlsAddr = ""
			m.opt.FileLogger.Error("tls config error:" + err.Error())
		}
	}
	// mqtt tls service
	if b, ok := toolbox.CheckTCPAddr(m.opt.MqttTlsAddr); ok {
		err = m.svr.AddListener(listeners.NewTCP(listeners.Config{
			ID:        "mqtt+tls",
			Address:   b.String(),
			TLSConfig: tl,
		}))
		if err != nil {
			m.opt.FileLogger.Error("[mqtt-broker] start tls service error: " + err.Error())
		}
	}
	// mqtt service
	if b, ok := toolbox.CheckTCPAddr(m.opt.MqttAddr); ok {
		err = m.svr.AddListener(listeners.NewTCP(listeners.Config{
			ID:        "mqtt",
			Address:   b.String(),
			TLSConfig: nil,
		}))
		if err != nil {
			m.opt.FileLogger.Error("[mqtt-broker] start mqtt service error: " + err.Error())
		}
	}
	// websocket service
	if b, ok := toolbox.CheckTCPAddr(m.opt.WSAddr); ok {
		err = m.svr.AddListener(listeners.NewWebsocket(listeners.Config{
			ID:        "ws",
			Address:   b.String(),
			TLSConfig: tl,
		}))
		if err != nil {
			m.opt.FileLogger.Error("[mqtt-broker] start ws service error: " + err.Error())
		}
	}
	// http status service
	if b, ok := toolbox.CheckTCPAddr(m.opt.WebAddr); ok {
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
			Address: b.String(),
		},
			m.svr.Info,
			m.svr.Clients,
			&Lopt{
				PortMqtt: m.opt.MqttAddr,
				PortTLS:  m.opt.MqttTlsAddr,
				PortWS:   m.opt.WSAddr,
				Auth:     userMap,
			},
		))
		if err != nil {
			m.opt.FileLogger.Error("[mqtt-broker] start web service error: " + err.Error())
		}
	}
	// start serve
	err = m.svr.Serve()
	if err != nil {
		m.opt.FileLogger.Error("[mqtt-broker] serve error: " + err.Error())
		return err
	}
	m.opt.FileLogger.System("[mqtt-broker] start success")
	return nil
}

func (m *MqttServer) CoreVersion() string {
	return mqtt.Version
}

// Subscribe use inline client to receive message
func (m *MqttServer) Subscribe(filter string, subscriptionId int, handler mqtt.InlineSubFn) error {
	return m.svr.Subscribe(filter, subscriptionId, handler)
}

// Publish use inline client publish a message,retain==false
func (m *MqttServer) Publish(topic string, payload []byte, qos byte) error {
	return m.svr.Publish(topic, payload, false, qos)
}
