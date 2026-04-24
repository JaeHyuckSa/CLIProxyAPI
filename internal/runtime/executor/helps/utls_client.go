package helps

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

const (
	// maxConnAge limits how long an HTTP/2 connection is reused before forcing
	// a fresh one. High stream IDs on a single connection correlate with
	// INTERNAL_ERROR from the peer; cycling connections prevents accumulation.
	maxConnAge = 5 * time.Minute

	// maxConnsPerHost is the maximum number of HTTP/2 connections per host.
	// With 20-30 concurrent sessions, spreading across multiple connections
	// reduces per-connection stream count and lowers INTERNAL_ERROR risk.
	maxConnsPerHost = 4
)

// pooledConn wraps an HTTP/2 connection with its creation time.
type pooledConn struct {
	conn    *http2.ClientConn
	created time.Time
}

// utlsRoundTripper implements http.RoundTripper using utls with Chrome fingerprint
// to bypass Cloudflare's TLS fingerprinting on Anthropic domains.
type utlsRoundTripper struct {
	mu      sync.Mutex
	pools   map[string][]pooledConn // host -> connection pool
	pending map[string]*sync.Cond
	dialer  proxy.Dialer
}

func newUtlsRoundTripper(proxyURL string) *utlsRoundTripper {
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("utls: failed to configure proxy dialer for %q: %v", proxyURL, errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}
	return &utlsRoundTripper{
		pools:   make(map[string][]pooledConn),
		pending: make(map[string]*sync.Cond),
		dialer:  dialer,
	}
}

// pickConnection selects an available connection from the pool, evicting expired ones.
// Returns nil if no healthy connection is available.
func (t *utlsRoundTripper) pickConnection(host string) *http2.ClientConn {
	pool := t.pools[host]
	now := time.Now()

	// Compact: remove dead/expired connections
	alive := pool[:0]
	for _, pc := range pool {
		if pc.conn.CanTakeNewRequest() && now.Sub(pc.created) <= maxConnAge {
			alive = append(alive, pc)
		}
	}
	t.pools[host] = alive

	if len(alive) == 0 {
		return nil
	}

	// Return the last connection (most recently created) for better locality,
	// but if the pool is full, prefer distributing across connections.
	// Simple round-robin via least-recently-returned would add complexity;
	// instead just return the first available — HTTP/2 handles multiplexing.
	return alive[0].conn
}

func (t *utlsRoundTripper) getOrCreateConnection(host, addr string) (*http2.ClientConn, error) {
	t.mu.Lock()

	if conn := t.pickConnection(host); conn != nil {
		pool := t.pools[host]
		// If pool is not full, we can still add more connections for concurrency.
		// Only reuse existing if pool is at capacity.
		if len(pool) >= maxConnsPerHost {
			t.mu.Unlock()
			return conn, nil
		}
		// Pool has room — but we only create a new connection if there's contention.
		// For now, reuse what we have.
		t.mu.Unlock()
		return conn, nil
	}

	if cond, ok := t.pending[host]; ok {
		cond.Wait()
		if conn := t.pickConnection(host); conn != nil {
			t.mu.Unlock()
			return conn, nil
		}
	}

	cond := sync.NewCond(&t.mu)
	t.pending[host] = cond
	t.mu.Unlock()

	h2Conn, err := t.createConnection(host, addr)

	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.pending, host)
	cond.Broadcast()

	if err != nil {
		return nil, err
	}

	t.pools[host] = append(t.pools[host], pooledConn{conn: h2Conn, created: time.Now()})
	return h2Conn, nil
}

// growPool creates an additional connection if the pool has room.
// Called when an existing connection hits a stream error, suggesting it's overloaded.
func (t *utlsRoundTripper) growPool(host, addr string) (*http2.ClientConn, error) {
	t.mu.Lock()
	pool := t.pools[host]
	if len(pool) >= maxConnsPerHost {
		// Pool is full — just pick an existing healthy one
		if conn := t.pickConnection(host); conn != nil {
			t.mu.Unlock()
			return conn, nil
		}
	}
	t.mu.Unlock()

	h2Conn, err := t.createConnection(host, addr)
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	t.pools[host] = append(t.pools[host], pooledConn{conn: h2Conn, created: time.Now()})
	t.mu.Unlock()

	return h2Conn, nil
}

// removeConnection removes a specific connection from the pool.
func (t *utlsRoundTripper) removeConnection(host string, target *http2.ClientConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	pool := t.pools[host]
	for i, pc := range pool {
		if pc.conn == target {
			t.pools[host] = append(pool[:i], pool[i+1:]...)
			return
		}
	}
}

func (t *utlsRoundTripper) createConnection(host, addr string) (*http2.ClientConn, error) {
	conn, err := t.dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{ServerName: host}
	tlsConn := tls.UClient(conn, tlsConfig, tls.HelloChrome_Auto)

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	tr := &http2.Transport{
		// Detect stale connections: send a ping if no frame received for 15s.
		ReadIdleTimeout: 15 * time.Second,
		// If the ping response doesn't arrive within 5s, treat the connection as dead.
		PingTimeout: 5 * time.Second,
	}
	h2Conn, err := tr.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	return h2Conn, nil
}

func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	hostname := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(hostname, port)

	h2Conn, err := t.getOrCreateConnection(hostname, addr)
	if err != nil {
		return nil, err
	}

	resp, err := h2Conn.RoundTrip(req)
	if err != nil {
		t.removeConnection(hostname, h2Conn)

		// Retry once on HTTP/2 stream errors (e.g. INTERNAL_ERROR, REFUSED_STREAM).
		// Grow the pool to add a fresh connection for the retry.
		if isHTTP2StreamError(err) {
			log.Debugf("utls: HTTP/2 stream error on %s, retrying with new connection: %v", hostname, err)
			h2Conn, err = t.growPool(hostname, addr)
			if err != nil {
				return nil, err
			}
			return h2Conn.RoundTrip(req)
		}

		return nil, err
	}

	return resp, nil
}

// isHTTP2StreamError checks if the error is an HTTP/2 stream-level error
// (e.g. INTERNAL_ERROR, REFUSED_STREAM) that is safe to retry.
func isHTTP2StreamError(err error) bool {
	if err == nil {
		return false
	}
	var streamErr http2.StreamError
	if errors.As(err, &streamErr) {
		return true
	}
	// Also catch wrapped "stream error" messages from net/http2.
	errMsg := err.Error()
	return strings.Contains(errMsg, "INTERNAL_ERROR") ||
		strings.Contains(errMsg, "REFUSED_STREAM") ||
		strings.Contains(errMsg, "stream error")
}

// anthropicHosts contains the hosts that should use utls Chrome TLS fingerprint.
var anthropicHosts = map[string]struct{}{
	"api.anthropic.com": {},
}

// fallbackRoundTripper uses utls for Anthropic HTTPS hosts and falls back to
// standard transport for all other requests (non-HTTPS or non-Anthropic hosts).
type fallbackRoundTripper struct {
	utls     *utlsRoundTripper
	fallback http.RoundTripper
}

func (f *fallbackRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		if _, ok := anthropicHosts[strings.ToLower(req.URL.Hostname())]; ok {
			return f.utls.RoundTrip(req)
		}
	}
	return f.fallback.RoundTrip(req)
}

// NewUtlsHTTPClient creates an HTTP client using utls Chrome TLS fingerprint.
// Use this for Claude API requests to match real Claude Code's TLS behavior.
// Falls back to standard transport for non-HTTPS requests.
func NewUtlsHTTPClient(cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	var proxyURL string
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}

	utlsRT := newUtlsRoundTripper(proxyURL)

	var standardTransport http.RoundTripper = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	if proxyURL != "" {
		if transport := buildProxyTransport(proxyURL); transport != nil {
			standardTransport = transport
		}
	}

	client := &http.Client{
		Transport: &fallbackRoundTripper{
			utls:     utlsRT,
			fallback: standardTransport,
		},
	}
	if timeout > 0 {
		client.Timeout = timeout
	}
	return client
}
