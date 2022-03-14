package soju

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"gopkg.in/irc.v3"
	"nhooyr.io/websocket"

	"git.sr.ht/~emersion/soju/config"
)

// TODO: make configurable
var retryConnectMinDelay = time.Minute
var retryConnectMaxDelay = 10 * time.Minute
var retryConnectJitter = time.Minute
var connectTimeout = 15 * time.Second
var writeTimeout = 10 * time.Second
var upstreamMessageDelay = 2 * time.Second
var upstreamMessageBurst = 10
var backlogTimeout = 10 * time.Second
var handleDownstreamMessageTimeout = 10 * time.Second
var downstreamRegisterTimeout = 30 * time.Second
var chatHistoryLimit = 1000
var backlogLimit = 4000

type Logger interface {
	Printf(format string, v ...interface{})
	Debugf(format string, v ...interface{})
}

type logger struct {
	*log.Logger
	debug bool
}

func (l logger) Debugf(format string, v ...interface{}) {
	if !l.debug {
		return
	}
	l.Logger.Printf(format, v...)
}

func NewLogger(out io.Writer, debug bool) Logger {
	return logger{
		Logger: log.New(log.Writer(), "", log.LstdFlags),
		debug:  debug,
	}
}

type prefixLogger struct {
	logger Logger
	prefix string
}

var _ Logger = (*prefixLogger)(nil)

func (l *prefixLogger) Printf(format string, v ...interface{}) {
	v = append([]interface{}{l.prefix}, v...)
	l.logger.Printf("%v"+format, v...)
}

func (l *prefixLogger) Debugf(format string, v ...interface{}) {
	v = append([]interface{}{l.prefix}, v...)
	l.logger.Debugf("%v"+format, v...)
}

type int64Gauge struct {
	v int64 // atomic
}

func (g *int64Gauge) Add(delta int64) {
	atomic.AddInt64(&g.v, delta)
}

func (g *int64Gauge) Value() int64 {
	return atomic.LoadInt64(&g.v)
}

func (g *int64Gauge) Float64() float64 {
	return float64(g.Value())
}

type retryListener struct {
	net.Listener
	Logger Logger

	delay time.Duration
}

func (ln *retryListener) Accept() (net.Conn, error) {
	for {
		conn, err := ln.Listener.Accept()
		if ne, ok := err.(net.Error); ok && ne.Temporary() {
			if ln.delay == 0 {
				ln.delay = 5 * time.Millisecond
			} else {
				ln.delay *= 2
			}
			if max := 1 * time.Second; ln.delay > max {
				ln.delay = max
			}
			if ln.Logger != nil {
				ln.Logger.Printf("accept error (retrying in %v): %v", ln.delay, err)
			}
			time.Sleep(ln.delay)
		} else {
			ln.delay = 0
			return conn, err
		}
	}
}

type Config struct {
	Hostname        string
	Title           string
	LogPath         string
	HTTPOrigins     []string
	AcceptProxyIPs  config.IPSet
	MaxUserNetworks int
	MultiUpstream   bool
	MOTD            string
	UpstreamUserIPs []*net.IPNet
}

type Server struct {
	Logger          Logger
	Identd          *Identd               // can be nil
	MetricsRegistry prometheus.Registerer // can be nil

	config atomic.Value // *Config
	db     Database
	stopWG sync.WaitGroup

	lock      sync.Mutex
	listeners map[net.Listener]struct{}
	users     map[string]*user

	metrics struct {
		downstreams int64Gauge
		upstreams   int64Gauge

		upstreamOutMessagesTotal   prometheus.Counter
		upstreamInMessagesTotal    prometheus.Counter
		downstreamOutMessagesTotal prometheus.Counter
		downstreamInMessagesTotal  prometheus.Counter

		upstreamConnectErrorsTotal prometheus.Counter
	}
}

func NewServer(db Database) *Server {
	srv := &Server{
		Logger:    NewLogger(log.Writer(), true),
		db:        db,
		listeners: make(map[net.Listener]struct{}),
		users:     make(map[string]*user),
	}
	srv.config.Store(&Config{
		Hostname:        "localhost",
		MaxUserNetworks: -1,
		MultiUpstream:   true,
	})
	return srv
}

func (s *Server) prefix() *irc.Prefix {
	return &irc.Prefix{Name: s.Config().Hostname}
}

func (s *Server) Config() *Config {
	return s.config.Load().(*Config)
}

func (s *Server) SetConfig(cfg *Config) {
	s.config.Store(cfg)
}

func (s *Server) Start() error {
	s.registerMetrics()

	users, err := s.db.ListUsers(context.TODO())
	if err != nil {
		return err
	}

	s.lock.Lock()
	for i := range users {
		s.addUserLocked(&users[i])
	}
	s.lock.Unlock()

	return nil
}

func (s *Server) registerMetrics() {
	factory := promauto.With(s.MetricsRegistry)

	factory.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "soju_users_active",
		Help: "Current number of active users",
	}, func() float64 {
		s.lock.Lock()
		n := len(s.users)
		s.lock.Unlock()
		return float64(n)
	})

	factory.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "soju_downstreams_active",
		Help: "Current number of downstream connections",
	}, s.metrics.downstreams.Float64)

	factory.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "soju_upstreams_active",
		Help: "Current number of upstream connections",
	}, s.metrics.upstreams.Float64)

	s.metrics.upstreamOutMessagesTotal = factory.NewCounter(prometheus.CounterOpts{
		Name: "soju_upstream_out_messages_total",
		Help: "Total number of outgoing messages sent to upstream servers",
	})

	s.metrics.upstreamInMessagesTotal = factory.NewCounter(prometheus.CounterOpts{
		Name: "soju_upstream_in_messages_total",
		Help: "Total number of incoming messages received from upstream servers",
	})

	s.metrics.downstreamOutMessagesTotal = factory.NewCounter(prometheus.CounterOpts{
		Name: "soju_downstream_out_messages_total",
		Help: "Total number of outgoing messages sent to downstream clients",
	})

	s.metrics.downstreamInMessagesTotal = factory.NewCounter(prometheus.CounterOpts{
		Name: "soju_downstream_in_messages_total",
		Help: "Total number of incoming messages received from downstream clients",
	})

	s.metrics.upstreamConnectErrorsTotal = factory.NewCounter(prometheus.CounterOpts{
		Name: "soju_upstream_connect_errors_total",
		Help: "Total number of upstream connection errors",
	})
}

func (s *Server) Shutdown() {
	s.lock.Lock()
	for ln := range s.listeners {
		if err := ln.Close(); err != nil {
			s.Logger.Printf("failed to stop listener: %v", err)
		}
	}
	for _, u := range s.users {
		u.events <- eventStop{}
	}
	s.lock.Unlock()

	s.stopWG.Wait()

	if err := s.db.Close(); err != nil {
		s.Logger.Printf("failed to close DB: %v", err)
	}
}

func (s *Server) createUser(ctx context.Context, user *User) (*user, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if _, ok := s.users[user.Username]; ok {
		return nil, fmt.Errorf("user %q already exists", user.Username)
	}

	err := s.db.StoreUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("could not create user in db: %v", err)
	}

	return s.addUserLocked(user), nil
}

func (s *Server) forEachUser(f func(*user)) {
	s.lock.Lock()
	for _, u := range s.users {
		f(u)
	}
	s.lock.Unlock()
}

func (s *Server) getUser(name string) *user {
	s.lock.Lock()
	u := s.users[name]
	s.lock.Unlock()
	return u
}

func (s *Server) addUserLocked(user *User) *user {
	s.Logger.Printf("starting bouncer for user %q", user.Username)
	u := newUser(s, user)
	s.users[u.Username] = u

	s.stopWG.Add(1)

	go func() {
		defer func() {
			if err := recover(); err != nil {
				s.Logger.Printf("panic serving user %q: %v\n%v", user.Username, err, debug.Stack())
			}

			s.lock.Lock()
			delete(s.users, u.Username)
			s.lock.Unlock()

			s.stopWG.Done()
		}()

		u.run()
	}()

	return u
}

var lastDownstreamID uint64 = 0

func (s *Server) handle(ic ircConn) {
	defer func() {
		if err := recover(); err != nil {
			s.Logger.Printf("panic serving downstream %q: %v\n%v", ic.RemoteAddr(), err, debug.Stack())
		}
	}()

	s.metrics.downstreams.Add(1)
	id := atomic.AddUint64(&lastDownstreamID, 1)
	dc := newDownstreamConn(s, ic, id)
	if err := dc.runUntilRegistered(); err != nil {
		if !errors.Is(err, io.EOF) {
			dc.logger.Printf("%v", err)
		}
	} else {
		dc.user.events <- eventDownstreamConnected{dc}
		if err := dc.readMessages(dc.user.events); err != nil {
			dc.logger.Printf("%v", err)
		}
		dc.user.events <- eventDownstreamDisconnected{dc}
	}
	dc.Close()
	s.metrics.downstreams.Add(-1)
}

func (s *Server) Serve(ln net.Listener) error {
	ln = &retryListener{
		Listener: ln,
		Logger:   &prefixLogger{logger: s.Logger, prefix: fmt.Sprintf("listener %v: ", ln.Addr())},
	}

	s.lock.Lock()
	s.listeners[ln] = struct{}{}
	s.lock.Unlock()

	s.stopWG.Add(1)

	defer func() {
		s.lock.Lock()
		delete(s.listeners, ln)
		s.lock.Unlock()

		s.stopWG.Done()
	}()

	for {
		conn, err := ln.Accept()
		if isErrClosed(err) {
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to accept connection: %v", err)
		}

		go s.handle(newNetIRCConn(conn))
	}
}

type GamjaServerConfig struct {
	URL         string `json:"url"`
	Auth        string `json:"auth"`
	Nick        string `json:"nick"`
	AutoConnect bool   `json:"autoconnect"`
	Ping        int    `json:"ping"`
}

type GamjaConfig struct {
	Server GamjaServerConfig `json:"server"`
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var srhtAuth *SrhtAuth
	if cookie, _ := req.Cookie("sr.ht.unified-login.v1"); cookie != nil {
		var err error
		if srhtAuth, err = checkSrhtCookie(req.Context(), cookie); err != nil {
			s.Logger.Printf("sr.ht cookie auth failed: %v", err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	if req.URL.Path == "/config.json" {
		w.Header().Set("Content-Type", "application/json")
		nick := "user"
		if srhtAuth != nil {
			nick = srhtAuth.Username
		}
		json.NewEncoder(w).Encode(GamjaConfig{
			Server: GamjaServerConfig{
				URL:         "/socket",
				Auth:        "external",
				Nick:        nick,
				AutoConnect: true,
				Ping:        500,
			},
		})
		return
	}

	conn, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		Subprotocols:   []string{"text.ircv3.net"}, // non-compliant, fight me
		OriginPatterns: s.Config().HTTPOrigins,
	})
	if err != nil {
		s.Logger.Printf("failed to serve HTTP connection: %v", err)
		return
	}

	isProxy := false
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			isProxy = s.Config().AcceptProxyIPs.Contains(ip)
		}
	}

	// Only trust the Forwarded header field if this is a trusted proxy IP
	// to prevent users from spoofing the remote address
	remoteAddr := req.RemoteAddr
	if isProxy {
		forwarded := parseForwarded(req.Header)
		if forwarded["for"] != "" {
			remoteAddr = forwarded["for"]
		}
	}

	ircConn := newWebsocketIRCConn(conn, remoteAddr)
	if srhtAuth != nil {
		ircConn = srhtAuthIRCConn{ircConn, srhtAuth}
	}

	s.handle(ircConn)
}

func parseForwarded(h http.Header) map[string]string {
	forwarded := h.Get("Forwarded")
	if forwarded == "" {
		return map[string]string{
			"for":   h.Get("X-Forwarded-For"),
			"proto": h.Get("X-Forwarded-Proto"),
			"host":  h.Get("X-Forwarded-Host"),
		}
	}
	// Hack to easily parse header parameters
	_, params, _ := mime.ParseMediaType("hack; " + forwarded)
	return params
}

type ServerStats struct {
	Users       int
	Downstreams int64
	Upstreams   int64
}

func (s *Server) Stats() *ServerStats {
	var stats ServerStats
	s.lock.Lock()
	stats.Users = len(s.users)
	s.lock.Unlock()
	stats.Downstreams = s.metrics.downstreams.Value()
	stats.Upstreams = s.metrics.upstreams.Value()
	return &stats
}
