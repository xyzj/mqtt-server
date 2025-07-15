package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/xyzj/mqtt-server/cmd/server"
	"github.com/xyzj/mqtt-server/hooks/auth"
	"github.com/xyzj/toolbox"
	"github.com/xyzj/toolbox/config"
	"github.com/xyzj/toolbox/crypto"
	"github.com/xyzj/toolbox/gocmd"
	"github.com/xyzj/toolbox/json"
	"github.com/xyzj/toolbox/logger"
	"github.com/xyzj/toolbox/pathtool"
)

var (
	gover       = ""
	cover       = ""
	version     = ""
	confname    = "go-mqttd.conf"
	confile     = flag.String("config", "", "config file path, default is "+confname)
	authfile    = flag.String("auth", "", "auth file path")
	logfile     = flag.String("log2file", "", "logfile path")
	disableAuth = flag.Bool("disable-auth", false, "disable auth check, ignore -auth")
	codedPwd    = flag.Bool("coded-pwd", false, "The 'password' in the auth file is coded by package github.com/xyzj/toolbox/crypto")
)

type svrOpt struct {
	conf     *config.File
	mqtt     string // mqtt port
	tls      string // mqtt+tls port
	web      string // http status port
	ws       string // websocket port
	cert     string
	key      string
	rootca   string
	msgtimeo int // message timeout in seconds
	bufSize  int // read, write buffer size
}

func loadConf(configfile string) *svrOpt {
	conf := config.NewConfig("")
	//  load config
	conf.FromFile(configfile)
	o := &svrOpt{}
	o.tls = conf.GetDefault(&config.Item{
		Key:     "port_tls",
		Value:   config.NewValue("1881"),
		Comment: "mqtt+tls port",
	}).String()
	o.mqtt = conf.GetDefault(&config.Item{
		Key:     "port_mqtt",
		Value:   config.NewValue("1883"),
		Comment: "mqtt port",
	}).String()
	o.web = conf.GetDefault(&config.Item{
		Key:     "port_web",
		Value:   config.NewValue("1880"),
		Comment: "http status port",
	}).String()
	o.ws = conf.GetDefault(&config.Item{
		Key:     "port_ws",
		Value:   config.EmptyValue,
		Comment: "websocket port, default: 1882",
	}).String()
	o.cert = conf.GetDefault(&config.Item{
		Key:     "tls_cert_file",
		Value:   config.NewValue("cert.ec.pem"),
		Comment: "tls cert file path",
	}).String()
	o.key = conf.GetDefault(&config.Item{
		Key:     "tls_key_file",
		Value:   config.NewValue("cert-key.ec.pem"),
		Comment: "tls key file path",
	}).String()
	o.rootca = conf.GetDefault(&config.Item{
		Key:     "tls_ca_file",
		Value:   config.EmptyValue,
		Comment: "tls root ca file path",
	}).String()
	o.msgtimeo = conf.GetDefault(&config.Item{
		Key:     "message_timeout",
		Value:   config.NewInt64Value(3600),
		Comment: "message expire time (seconds)",
	}).TryInt()
	o.bufSize = conf.GetItem("buffer_size").TryInt()
	if o.bufSize < 8192 {
		o.bufSize = 8192
	}
	o.conf = conf
	if o.tls != "" && !strings.HasPrefix(o.tls, ":") {
		o.tls = ":" + o.tls
	}
	if o.mqtt != "" && !strings.HasPrefix(o.mqtt, ":") {
		o.mqtt = ":" + o.mqtt
	}
	if o.web != "" && !strings.HasPrefix(o.web, ":") {
		o.web = ":" + o.web
	}
	if o.ws != "" && !strings.HasPrefix(o.ws, ":") {
		o.ws = ":" + o.ws
	}
	// save config
	conf.ToFile()
	return o
}

type ver struct {
	Core    string `json:"core_ver"`
	GoVer   string `json:"go_ver"`
	Version string `json:"version"`
}

func main() {
	var svr *server.MqttServer
	bv, _ := json.MarshalIndent(&ver{
		Core:    cover,
		GoVer:   gover,
		Version: version,
	}, "", "  ")
	p := gocmd.DefaultProgram(
		&gocmd.Info{
			Ver:      string(bv),
			Title:    "golang mqtt broker",
			Descript: "based on mochi-mqtt, support MQTT v3.11 and MQTT v5.0",
		}).
		AddCommand(&gocmd.Command{
			Name:     "initauth",
			Descript: "init a sample authfile",
			RunWithExitCode: func(pi *gocmd.ProcInfo) int {
				if server.InitAuthfile(pathtool.JoinPathFromHere("auth.yaml")) != nil {
					return 1
				}
				return 0
			},
		}).
		AddCommand(&gocmd.Command{
			Name:     "code-password",
			Descript: "code password for auth.yaml",
			RunWithExitCode: func(pi *gocmd.ProcInfo) int {
				var pwd string
				print("Password: ")
				if _, err := fmt.Scanf("%s", &pwd); err != nil {
					println(err.Error())
					return 1
				}
				println(crypto.ObfuscationString(pwd))
				return 0
			},
		}).
		AddCommand(&gocmd.Command{
			Name:     "genecc",
			Descript: "generate ECC certificate files",
			RunWithExitCode: func(pi *gocmd.ProcInfo) int {
				c := crypto.NewECC()
				ips, _, err := toolbox.GlobalIPs()
				if err != nil {
					ips = []string{"127.0.0.1"}
				}
				local := false
				for _, v := range ips {
					if v == "127.0.0.1" {
						local = true
					}
				}
				if !local {
					ips = append(ips, "127.0.0.1")
				}
				if err := c.CreateCert(&crypto.CertOpt{
					DNS:     []string{"localhost"},
					IP:      ips,
					RootKey: pathtool.JoinPathFromHere("root-key.ec.pem"),
					RootCa:  pathtool.JoinPathFromHere("root.ec.pem"),
				}); err != nil {
					println(err.Error())
					return 1
				}
				println("done.")
				return 0
			},
		}).
		AfterStop(func() {
			svr.Stop()
		})
	p.Execute()

	if *confile == "" {
		*confile = pathtool.JoinPathFromHere(confname)
	}
	o := loadConf(*confile)
	ac := &auth.Ledger{}
	if *authfile != "" {
		var err error
		ac, err = server.FromAuthfile(*authfile, *codedPwd)
		if err != nil {
			println(err.Error())
			p.Exit(1)
			return
		}
	}
	// add an admin account
	if ac.Users == nil {
		ac.Users = make(map[string]auth.UserRule)
	}
	if _, ok := ac.Users["YoRHa"]; !ok {
		ac.Users["YoRHa"] = auth.UserRule{
			Username: "YoRHa",
			Password: "no2typeB",
		}
	}
	opt := &server.Opt{
		MqttTlsAddr:         o.tls,
		WebAddr:             o.web,
		WSAddr:              o.ws,
		MqttAddr:            o.mqtt,
		Cert:                o.cert,
		Key:                 o.key,
		RootCA:              o.rootca,
		DisableAuth:         *disableAuth,
		AuthConfig:          ac,
		ClientsBufferSize:   o.bufSize,
		MaxMsgExpirySeconds: o.msgtimeo,
		FileLogger:          logger.NewConsoleLogger(),
	}
	if *logfile != "" {
		opt.FileLogger = logger.NewMultiLogger(
			logger.NewLogger(logger.LogInfo, logger.OptFilename(filepath.Base(*logfile)),
				logger.OptFileDir(filepath.Dir(*logfile)),
				logger.OptFileDays(30),
				logger.OptCompressFile(true),
			),
			logger.NewConsoleLogger(),
		)
	}
	svr = server.NewServer(opt)
	svr.Run()
}
