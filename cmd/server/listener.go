package server

import (
	"context"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin/render"
	mqtt "github.com/xyzj/mqtt-server"
	"github.com/xyzj/mqtt-server/listeners"
	"github.com/xyzj/mqtt-server/system"
	"github.com/xyzj/toolbox"
	"github.com/xyzj/toolbox/json"
	"github.com/xyzj/toolbox/proc"
)

var t1 = `<html lang="zh-cn">
<head>
    <meta content="text/html; charset=utf-8" http-equiv="content-type" />
    <script language="JavaScript">
        function myrefresh() {
            window.location.reload();
        }
        setTimeout('myrefresh()', 180000); // refresh 180s
    </script>
    <style type="text/css">
        a {
            color: #4183C4;
            font-size: 16px;
        }
        h1,
        h2,
        h3,
        h4,
        h5,
        h6 {
            margin: 20px 0 10px;
            padding: 0;
            font-weight: bold;
            -webkit-font-smoothing: antialiased;
            cursor: text;
            position: relative;
        }
        h1 {
            font-size: 28px;
            color: black;
        }
        h2 {
            font-size: 24px;
            border-bottom: 1px solid #cccccc;
            color: black;
        }
        h3 {
            font-size: 18px;
        }
        h4 {
            font-size: 16px;
        }
        h5 {
            font-size: 14px;
        }
        h6 {
            color: #777777;
            font-size: 14px;
        }
        table {
            padding: 0;
        }
        table tr {
            border-top: 1px solid #000000;
            background-color: #ffffff;
            margin: 0;
            padding: 0;
        }
        table tr td:nth-of-type(2) {
            text-align: left;
        }
        table tr td:nth-of-type(7) {
            text-align: left;
            width: 700px;
            white-space: pre-wrap;
        }
        table tr:nth-child(2n) {
            background-color: #eeffee;
        }
        table tr th {
            font-weight: bold;
            background-color: #fffddd;
            border: 1px solid #cccccc;
            text-align: center;
            margin: 0;
            padding: 6px 13px;
        }
        table tr td {
            border: 1px solid #cccccc;
            text-align: center;
            margin: 0;
            padding: 6px 13px;
        }
        table tr th :first-child,
        table tr td :first-child {
            margin-top: 0;
        }
        table tr th :last-child,
        table tr td :last-child {
            margin-bottom: 0;
        }
    </style>
</head>
<title>Broker Information</title>
{{template "body" .}}

</html>`

var t3 = `{{define "body"}}
<body>
    <h3>Current Time:</h3><a>{{.timer}}</a>
    <h3>Uptime</h3><a>{{.uptime}}</a>
    <h3>Listeners:</h3><a>{{.listener}}</a>
    <h3>Clients</h3><a>{{.counts}}</a>
    <table>
        <thead>
            <tr>
                <th>Client User</th>
                <th>Client ID</th>
                <th>Client IP</th>
                <th>Client Ver</th>
                <th>Protocol</th>
                <th>Subscribes</th>
                <th>Subscribe Detail</th>
            </tr>
        </thead>
        <tbody>
            {{range $idx, $elem := .clients}}
            <tr>
                {{range $key,$value:=$elem}}
                <td>{{$value}}</td>
                {{end}}
            </tr>
            {{end}}
        </tbody>
    </table>
</body>
	{{end}}`

type Lopt struct {
	// mqtt port
	PortMqtt string
	// mqtt+tls port
	PortTLS string
	// http status port
	PortWeb string
	// websocket port
	PortWS string
	// Authfile string
	Auth map[string]string
}

func (o *Lopt) String() string {
	s := []string{}
	if o.PortMqtt != "" {
		s = append(s, "mqtt: "+o.PortMqtt)
	}
	if o.PortTLS != "" {
		s = append(s, "mqtt+tls: "+o.PortTLS)
	}
	if o.PortWS != "" {
		s = append(s, "ws: "+o.PortWS)
	}
	return strings.Join(s, "; ")
}

// HTTPStats is a listener for presenting the server $SYS stats on a JSON http endpoint.
type HTTPStats struct {
	sync.RWMutex
	config      *listeners.Config // configuration values for the listener
	listen      *http.Server      // the http server
	sysInfo     *system.Info      // pointers to the server data
	clientsInfo *mqtt.Clients     // pointers to the server data
	log         *slog.Logger      // server logger
	lopt        *Lopt
	id          string // the internal id of the listener
	address     string // the network address to bind to
	end         uint32 // ensure the close methods are only called once
}

// NewHTTPStats initialises and returns a new HTTP listener, listening on an address.
func NewHTTPStats(config *listeners.Config, sysInfo *system.Info, cliInfo *mqtt.Clients, lopt *Lopt) *HTTPStats {
	if config == nil {
		config = new(listeners.Config)
	}
	return &HTTPStats{
		id:          config.ID,
		address:     config.Address,
		sysInfo:     sysInfo,
		clientsInfo: cliInfo,
		config:      config,
		lopt:        lopt,
	}
}

// ID returns the id of the listener.
func (l *HTTPStats) ID() string {
	return l.id
}

// Address returns the address of the listener.
func (l *HTTPStats) Address() string {
	return l.address
}

// Protocol returns the address of the listener.
func (l *HTTPStats) Protocol() string {
	if l.listen != nil && l.listen.TLSConfig != nil {
		return "https"
	}

	return "http"
}

// Init initializes the listener.
func (l *HTTPStats) Init(log *slog.Logger) error {
	l.log = log
	p := proc.StartRecord(&proc.RecordOpt{
		Timer:       time.Second * 60,
		Name:        "MQTT Broker",
		DataTimeout: time.Hour * 24 * 7,
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/information", toolbox.HTTPBasicAuth(l.lopt.Auth, l.infoHandler))
	mux.HandleFunc("/connections", toolbox.HTTPBasicAuth(l.lopt.Auth, l.clientHandler))
	mux.HandleFunc("/clientsrawdata", toolbox.HTTPBasicAuth(l.lopt.Auth, l.debugHandler))
	mux.HandleFunc("/processrecords", toolbox.HTTPBasicAuth(l.lopt.Auth, p.HTTPHandler))
	l.listen = &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		Addr:         l.address,
		Handler:      mux,
	}

	if l.config.TLSConfig != nil {
		l.listen.TLSConfig = l.config.TLSConfig
	}

	return nil
}

// Serve starts listening for new connections and serving responses.
func (l *HTTPStats) Serve(establish listeners.EstablishFn) {
	var err error
	if l.listen.TLSConfig != nil {
		err = l.listen.ListenAndServeTLS("", "")
	} else {
		err = l.listen.ListenAndServe()
	}

	// After the listener has been shutdown, no need to print the http.ErrServerClosed error.
	if err != nil && atomic.LoadUint32(&l.end) == 0 {
		l.log.Error("failed to serve.", "error", err, "listener", l.id)
	}
}

// Close closes the listener and any client connections.
func (l *HTTPStats) Close(closeClients listeners.CloseFn) {
	l.Lock()
	defer l.Unlock()

	if atomic.CompareAndSwapUint32(&l.end, 0, 1) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = l.listen.Shutdown(ctx)
	}

	closeClients(l.id)
}

// clientHandler is an HTTP handler which outputs the $SYS stats as JSON.
func (l *HTTPStats) clientHandler(w http.ResponseWriter, req *http.Request) {
	info := l.clientsInfo.GetAll()
	sss := make([][]string, 0, len(info))
	counts := make(map[string]int)
	for _, v := range info {
		if v.Net.Listener == "local" || v.ID == "inline" {
			continue
		}
		ss := make([]string, 0)
		for k := range v.State.Subscriptions.GetAll() {
			ss = append(ss, k)
		}
		sort.Slice(ss, func(i, j int) bool {
			return ss[i] < ss[j]
		})
		sss = append(sss, []string{json.String(v.Properties.Username), v.ID, v.Net.Remote, strconv.Itoa(int(v.Properties.ProtocolVersion)), v.Net.Listener, strconv.Itoa(v.State.Subscriptions.Len()), strings.Join(ss, "\n")}) //

		if vv, ok := counts[v.Net.Listener]; ok {
			counts[v.Net.Listener] = vv + 1
		} else {
			counts[v.Net.Listener] = 1
		}
	}
	sort.Slice(sss, func(i, j int) bool {
		return sss[i][0]+sss[i][1] < sss[j][0]+sss[j][1]
	})
	c := []string{}
	for k, v := range counts {
		c = append(c, k+": "+strconv.Itoa(v))
	}
	sort.Slice(c, func(i, j int) bool {
		return c[i] < c[j]
	})
	d := map[string]any{
		"timer":    time.Now().String(),
		"uptime":   toolbox.Seconds2String(l.sysInfo.Uptime),
		"listener": l.lopt.String(),
		"counts":   strings.Join(c, "; "),
		"clients":  sss,
	}
	t, _ := template.New("systemStatus").Parse(t1 + t3)
	h := render.HTML{
		Name:     "systemStatus",
		Data:     d,
		Template: t,
	}
	h.WriteContentType(w)
	h.Render(w)
}

// infoHandler is an HTTP handler which outputs the $SYS stats as JSON.
func (l *HTTPStats) infoHandler(w http.ResponseWriter, req *http.Request) {
	info := *l.sysInfo.Clone()

	out, err := json.MarshalIndent(info, "", "\t")
	if err != nil {
		_, _ = io.WriteString(w, err.Error())
	}

	_, _ = w.Write(out)
}

// debugHandler is an HTTP handler which outputs the $SYS stats as JSON.
func (l *HTTPStats) debugHandler(w http.ResponseWriter, req *http.Request) {
	info := l.clientsInfo.GetAll()
	for _, v := range info {
		s, err := json.MarshalIndent(v, "", "  ")
		if err == nil {
			w.Write(s)
			w.Write([]byte{10})
		}
	}
}
