package claude

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/httpwire"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

type claudeRefreshHandshakeTimeoutContextKey struct{}

var claudeOAuthRefreshHeaderOrder = []string{
	"Accept",
	"Content-Type",
	"User-Agent",
	"Content-Length",
	"Accept-Encoding",
	"Host",
	"Connection",
}

// claudeOAuthInspectHeaderOrder is the order the native client emits for the
// authenticated Axios GET lookups on the OAuth control plane, covering both the
// account profile and the claude_cli roles companion request.
var claudeOAuthInspectHeaderOrder = []string{
	"Accept",
	"Content-Type",
	"Authorization",
	"Cache-Control",
	"User-Agent",
	"Accept-Encoding",
	"Host",
	"Connection",
}

// claudeOAuthInspectTargets are the authenticated control-plane GET paths that
// use claudeOAuthInspectHeaderOrder.
var claudeOAuthInspectTargets = []string{
	"/api/oauth/profile",
	"/api/oauth/claude_cli/roles",
}

func claudeOAuthRequestHeaderOrder(method, requestTarget string) []string {
	if method == http.MethodGet {
		for _, target := range claudeOAuthInspectTargets {
			if strings.HasPrefix(requestTarget, target) {
				return claudeOAuthInspectHeaderOrder
			}
		}
	}
	return claudeOAuthRefreshHeaderOrder
}

// newClaudeOAuthTLSConfig builds the uTLS config for one control-plane dial.
//
// The native client (Bun / BoringSSL) performs a full handshake on every
// connection and never presents pre_shared_key, so no session cache is attached
// and tickets are disabled. OmitEmptyPsk keeps the extension silent;
// PreferSkipResumptionOnNilExtension is defense in depth against a HelloCustom
// resumption panic should a cache ever be wired in again.
func newClaudeOAuthTLSConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName:                         host,
		SessionTicketsDisabled:             true,
		OmitEmptyPsk:                       true,
		PreferSkipResumptionOnNilExtension: true,
	}
}

// claudeOAuthTLSClientHelloSpec reproduces the ClientHello the native Claude Code
// 2.1.274 binary (Bun 1.4.3 / BoringSSL) emits from its Axios / node:https path,
// which carries the OAuth control-plane calls (platform.claude.com token refresh
// and the api.anthropic.com profile and role lookups). It was captured 2026-09-18
// from that client's direct api.anthropic.com connections. Unlike the fetch
// profile used for inference it advertises no ALPN, status_request or SCT
// extension and orders cipher suites the Node.js way (RSA before ECDSA, with
// ECDHE-RSA-AES128-SHA256), so it negotiates HTTP/1.1 without a protocol.
func claudeOAuthTLSClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMin:         tls.VersionTLS12,
		TLSVersMax:         tls.VersionTLS13,
		CompressionMethods: []uint8{0},
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.ExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&tls.SessionTicketExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1,
			}},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519MLKEM768}, {Group: tls.X25519}}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}},
			// pre_shared_key MUST be the final extension (RFC 8446 4.2.11). The native
			// client never resumes and no session cache is attached, so it contributes
			// zero bytes; it stays listed only to keep the ordering rule explicit.
			&tls.UtlsPreSharedKeyExtension{},
		},
	}
}

// utlsRoundTripper uses Claude Code's OAuth control-plane TLS and HTTP/1.1
// profile while retaining net/http proxy, cancellation, response parsing and
// connection lifecycle semantics.
type utlsRoundTripper struct {
	dialer    proxy.Dialer
	transport *http.Transport
}

func newUtlsRoundTripper(cfg *config.SDKConfig) *utlsRoundTripper {
	return newUtlsRoundTripperForCredential(cfg, "")
}

// newUtlsRoundTripperForCredential builds the control-plane transport for one
// credential. An empty credential scope is the anonymous login flow, which has
// no account identity to protect yet.
// newUtlsRoundTripperForCredential builds the control-plane transport for one
// credential. TLS sessions are never resumed, so the credential no longer scopes
// any TLS state; the parameter names the account the dial serves for callers.
func newUtlsRoundTripperForCredential(cfg *config.SDKConfig, _ string) *utlsRoundTripper {
	var dialer proxy.Dialer = proxy.Direct
	if cfg != nil {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(cfg.ProxyURL)
		if errBuild != nil {
			log.Errorf("failed to configure proxy dialer for %q: %v", proxyutil.Redact(cfg.ProxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}

	roundTripper := &utlsRoundTripper{dialer: dialer}
	roundTripper.transport = &http.Transport{
		ForceAttemptHTTP2: false,
		DialTLSContext:    roundTripper.dialTLSContext,
	}
	return roundTripper
}

func (t *utlsRoundTripper) dialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	if contextDialer, ok := t.dialer.(proxy.ContextDialer); ok {
		conn, err = contextDialer.DialContext(ctx, network, addr)
	} else {
		conn, err = t.dialer.Dial(network, addr)
	}
	if err != nil {
		return nil, fmt.Errorf("claude oauth tls: dial upstream: %w", err)
	}

	host, _, errSplit := net.SplitHostPort(addr)
	if errSplit != nil {
		if errClose := conn.Close(); errClose != nil {
			log.Debugf("claude oauth tls: close failed connection: %v", errClose)
		}
		return nil, fmt.Errorf("claude oauth tls: split upstream address: %w", errSplit)
	}
	tlsConn := tls.UClient(conn, newClaudeOAuthTLSConfig(host), tls.HelloCustom)
	if errPreset := tlsConn.ApplyPreset(claudeOAuthTLSClientHelloSpec()); errPreset != nil {
		if errClose := tlsConn.Close(); errClose != nil {
			log.Debugf("claude oauth tls: close connection after preset failure: %v", errClose)
		}
		return nil, fmt.Errorf("claude oauth tls: apply ClientHello: %w", errPreset)
	}
	handshakeCtx := ctx
	if handshakeTimeout, _ := ctx.Value(claudeRefreshHandshakeTimeoutContextKey{}).(time.Duration); handshakeTimeout > 0 {
		var cancelHandshake context.CancelFunc
		handshakeCtx, cancelHandshake = context.WithTimeout(ctx, handshakeTimeout)
		defer cancelHandshake()
	}
	if errHandshake := tlsConn.HandshakeContext(handshakeCtx); errHandshake != nil {
		if errClose := tlsConn.Close(); errClose != nil {
			log.Debugf("claude oauth tls: close connection after handshake failure: %v", errClose)
		}
		return nil, fmt.Errorf("claude oauth tls: handshake upstream: %w", errHandshake)
	}
	return httpwire.NewOrderedRequestConn(tlsConn, claudeOAuthRequestHeaderOrder), nil
}

func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(req)
}

func (t *utlsRoundTripper) CloseIdleConnections() {
	t.transport.CloseIdleConnections()
}

func NewAnthropicHttpClient(cfg *config.SDKConfig) *http.Client {
	return &http.Client{Transport: newUtlsRoundTripper(cfg)}
}

// NewAnthropicHttpClientForCredential is NewAnthropicHttpClient with TLS session
// resumption scoped to one credential.
func NewAnthropicHttpClientForCredential(cfg *config.SDKConfig, credential string) *http.Client {
	return &http.Client{Transport: newUtlsRoundTripperForCredential(cfg, credential)}
}
