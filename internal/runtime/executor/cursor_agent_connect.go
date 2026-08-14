package executor

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// Cursor CLI / AgentService wire constants captured from the installed
// cursor-agent 2026.08.11-e8db854 bundle. Live Run is HTTP/2 Connect bidi;
// API-key login is a JSON POST to /auth/exchange_user_api_key.
const (
	cursorAgentDefaultEndpoint = "https://api2.cursor.sh"
	cursorAgentAuthExchange    = "/auth/exchange_user_api_key"
	cursorAgentServicePath     = "/agent.v1.AgentService/Run"
	cursorConnectFrameHeader   = 5
)

func cursorAgentServiceURL(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = cursorAgentDefaultEndpoint
	}
	return strings.TrimSuffix(endpoint, "/") + cursorAgentServicePath
}

func cursorAuthEndpointOverride(auth *cliproxyauth.Auth, keys ...string) string {
	if auth == nil || auth.Attributes == nil {
		return ""
	}
	for _, key := range keys {
		if value := strings.TrimSpace(auth.Attributes[key]); value != "" {
			return value
		}
	}
	return ""
}

func cursorAgentEndpoint(e *CursorExecutor, auth *cliproxyauth.Auth) string {
	if e != nil {
		if endpoint := strings.TrimSpace(e.agentEndpoint); endpoint != "" {
			return endpoint
		}
	}
	if endpoint := cursorAuthEndpointOverride(auth, "cursor_agent_endpoint", "agent_endpoint"); endpoint != "" {
		return endpoint
	}
	if endpoint := strings.TrimSpace(os.Getenv("CURSOR_AGENT_ENDPOINT")); endpoint != "" {
		return endpoint
	}
	return cursorAgentDefaultEndpoint
}

func cursorAuthExchangeEndpoint(e *CursorExecutor, auth *cliproxyauth.Auth) string {
	if e != nil {
		if endpoint := strings.TrimSpace(e.authEndpoint); endpoint != "" {
			return endpoint
		}
	}
	if endpoint := cursorAuthEndpointOverride(auth, "cursor_auth_endpoint", "auth_endpoint"); endpoint != "" {
		return endpoint
	}
	if endpoint := strings.TrimSpace(os.Getenv("CURSOR_AUTH_ENDPOINT")); endpoint != "" {
		return endpoint
	}
	return cursorAgentDefaultEndpoint
}

type cursorConnectFrame struct {
	Flags   byte
	Payload []byte
}

func cursorEncodeConnectFrame(flags byte, payload []byte) []byte {
	out := make([]byte, cursorConnectFrameHeader+len(payload))
	out[0] = flags
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

func cursorDecodeConnectFrame(r io.Reader) (cursorConnectFrame, error) {
	var hdr [cursorConnectFrameHeader]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return cursorConnectFrame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[1:5])
	if n > 16*1024*1024 {
		return cursorConnectFrame{}, fmt.Errorf("cursor connect: frame too large (%d)", n)
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return cursorConnectFrame{}, err
		}
	}
	return cursorConnectFrame{Flags: hdr[0], Payload: payload}, nil
}

type cursorAgentJWT struct {
	Token     string
	ExpiresAt time.Time
}

func (e *CursorExecutor) cursorExchangeAPIKey(ctx context.Context, auth *cliproxyauth.Auth, backendURL string) (cursorAgentJWT, error) {
	info := cursorInfoFromAuth(auth)
	if info.apiKey == "" {
		return cursorAgentJWT{}, statusErr{code: http.StatusUnauthorized, msg: "cursor executor: missing api key"}
	}
	if strings.TrimSpace(backendURL) == "" {
		backendURL = cursorAgentDefaultEndpoint
	}
	// cursor-agent sends an empty JSON object. The API key is carried in the
	// Authorization header, which PrepareRequest adds below.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(backendURL, "/")+cursorAgentAuthExchange, bytes.NewReader([]byte("{}")))
	if err != nil {
		return cursorAgentJWT{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := e.PrepareRequest(req, auth); err != nil {
		return cursorAgentJWT{}, err
	}
	resp, err := e.cursorHTTPClient(ctx, auth).Do(req)
	if err != nil {
		return cursorAgentJWT{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return cursorAgentJWT{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return cursorAgentJWT{}, statusErr{code: resp.StatusCode, msg: string(raw)}
	}
	token := strings.TrimSpace(gjson.GetBytes(raw, "accessToken").String())
	if token == "" {
		// Keep the compatibility fallbacks for older test doubles/proxies, but
		// accessToken is the field used by the official CLI endpoint.
		token = strings.TrimSpace(gjson.GetBytes(raw, "token").String())
	}
	if token == "" {
		token = strings.TrimSpace(gjson.GetBytes(raw, "access_token").String())
	}
	if token == "" {
		return cursorAgentJWT{}, fmt.Errorf("cursor executor: auth exchange returned no token")
	}
	out := cursorAgentJWT{Token: token, ExpiresAt: time.Now().Add(time.Hour)}
	if exp := gjson.GetBytes(raw, "expiresIn").Int(); exp > 0 {
		out.ExpiresAt = time.Now().Add(time.Duration(exp) * time.Second)
	}
	return out, nil
}
