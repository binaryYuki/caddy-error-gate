package caddy_error_gate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

type mockHandler struct {
	status  int
	headers http.Header
	body    string
	err     error
}

func (m mockHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) error {
	if m.headers != nil {
		for k, vv := range m.headers {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
	}
	if m.status != 0 {
		w.WriteHeader(m.status)
	}
	if m.body != "" {
		w.Write([]byte(m.body))
	}
	return m.err
}

func TestErrorGate_NoIntercept(t *testing.T) {
	g := ErrorGate{
		MinStatus: 500,
		MaxStatus: 599,
	}
	if err := g.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	next := mockHandler{
		status: http.StatusOK,
		headers: http.Header{
			"Cache-Control": []string{"public, max-age=3600"},
			"ETag":          []string{"12345"},
		},
		body: "OK",
	}

	err := g.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
	if w.Body.String() != "OK" {
		t.Errorf("expected body %q, got %q", "OK", w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Errorf("expected Cache-Control to be preserved, got %q", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("ETag") != "12345" {
		t.Errorf("expected ETag to be preserved, got %q", w.Header().Get("ETag"))
	}
}

func TestErrorGate_InterceptHTML(t *testing.T) {
	g := ErrorGate{
		MinStatus: 500,
		MaxStatus: 599,
	}
	if err := g.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Accept-Language", "zh-CN")
	w := httptest.NewRecorder()

	next := mockHandler{
		status: http.StatusInternalServerError,
		headers: http.Header{
			"Cache-Control":                []string{"public, max-age=3600"},
			"Age":                          []string{"120"},
			"Cloudflare-CDN-Cache-Control": []string{"max-age=600"},
			"CDN-Cache-Control":            []string{"max-age=300"},
			"Surrogate-Control":            []string{"max-age=150"},
			"ETag":                         []string{"12345"},
			"Last-Modified":                []string{"yesterday"},
			"Content-Encoding":             []string{"gzip"},
			"Content-Length":               []string{"10"},
			"Access-Control-Allow-Origin":  []string{"*"},
			"X-Custom-Header":              []string{"hello"},
		},
		body: "Error!",
	}

	err := g.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	// Verify headers stripped
	for _, h := range []string{"Age", "Cloudflare-CDN-Cache-Control", "CDN-Cache-Control", "ETag", "Last-Modified", "Content-Encoding", "Content-Length"} {
		if val := w.Header().Get(h); val != "" {
			t.Errorf("header %s should have been stripped, got %q", h, val)
		}
	}

	// Verify cache control set to prevent caching
	if cc := w.Header().Get("Cache-Control"); cc != "no-store, max-age=0" {
		t.Errorf("expected Cache-Control to prevent caching, got %q", cc)
	}
	if sc := w.Header().Get("Surrogate-Control"); sc != "no-store" {
		t.Errorf("expected Surrogate-Control to prevent caching, got %q", sc)
	}
	if pragma := w.Header().Get("Pragma"); pragma != "no-cache" {
		t.Errorf("expected Pragma to be no-cache, got %q", pragma)
	}
	if exp := w.Header().Get("Expires"); exp != "0" {
		t.Errorf("expected Expires to be 0, got %q", exp)
	}

	// Verify preserved headers
	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "*" {
		t.Errorf("expected Access-Control-Allow-Origin to be preserved, got %q", origin)
	}
	if custom := w.Header().Get("X-Custom-Header"); custom != "hello" {
		t.Errorf("expected X-Custom-Header to be preserved, got %q", custom)
	}

	// Verify content type and content
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("expected Content-Type text/html; charset=utf-8, got %q", ct)
	}
	if !strings.Contains(w.Body.String(), "500 Internal Server Error") {
		t.Errorf("expected HTML body to contain error details, got %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Internal Server Error — 服务器无法完成该请求。") {
		t.Errorf("expected HTML body to contain standard error description, got %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "抱歉哦，服务器的小马达突然卡住了，程序员哥哥正在疯狂抢修中！") {
		t.Errorf("expected HTML body to contain cute error description, got %q", w.Body.String())
	}
	if w.Header().Get("x-Catyuki-Lb-Id") == "" {
		t.Error("expected trace ID header to be set")
	}
}

func TestErrorGate_InterceptJSON(t *testing.T) {
	g := ErrorGate{
		MinStatus: 500,
		MaxStatus: 599,
	}
	if err := g.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/users", nil)
	req.Header.Set("Accept-Language", "zh-CN")
	w := httptest.NewRecorder()

	next := mockHandler{
		status: http.StatusInternalServerError,
		headers: http.Header{
			"Cache-Control":               []string{"public, max-age=3600"},
			"Access-Control-Allow-Origin": []string{"*"},
		},
		body: "Error!",
	}

	err := g.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var jsonBody map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &jsonBody); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	if statusVal, ok := jsonBody["status"].(float64); !ok || int(statusVal) != 500 {
		t.Errorf("expected status 500, got %v", jsonBody["status"])
	}
	if codeVal, ok := jsonBody["code"].(string); !ok || codeVal != "Internal Server Error" {
		t.Errorf("expected code 'Internal Server Error', got %v", jsonBody["code"])
	}
	if traceVal, ok := jsonBody["traceId"].(string); !ok || traceVal == "" {
		t.Errorf("expected traceId, got %v", jsonBody["traceId"])
	}
	if descVal, ok := jsonBody["description"].(string); !ok || descVal != "抱歉哦，服务器的小马达突然卡住了，程序员哥哥正在疯狂抢修中！" {
		t.Errorf("expected description '抱歉哦，服务器的小马达突然卡住了，程序员哥哥正在疯狂抢修中！', got %v", jsonBody["description"])
	}
}

func TestErrorGate_CustomTemplates(t *testing.T) {
	// Create custom template files
	htmlFile, err := os.CreateTemp("", "test_template_*.html")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(htmlFile.Name())
	if _, err := htmlFile.WriteString("Custom HTML {{ .Status }} {{ .Text }} {{ .TraceID }}"); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	err = htmlFile.Close()
	if err != nil {
		return
	}

	jsonFile, err := os.CreateTemp("", "test_template_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			return
		}
	}(jsonFile.Name())
	if _, err := jsonFile.WriteString(`{"custom_status": {{ .Status }}, "trace": "{{ .TraceID }}"}`); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	err = jsonFile.Close()
	if err != nil {
		return
	}

	g := ErrorGate{
		MinStatus:    500,
		MaxStatus:    599,
		HTMLTemplate: htmlFile.Name(),
		JSONTemplate: jsonFile.Name(),
	}
	if err := g.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Test HTML request
	reqHTML := httptest.NewRequest("GET", "/test", nil)
	wHTML := httptest.NewRecorder()
	nextHTML := mockHandler{status: http.StatusInternalServerError}
	if err := g.ServeHTTP(wHTML, reqHTML, nextHTML); err != nil {
		t.Fatalf("ServeHTTP HTML failed: %v", err)
	}
	if !strings.HasPrefix(wHTML.Body.String(), "Custom HTML 500 Internal Server Error ") {
		t.Errorf("expected custom HTML rendering, got %q", wHTML.Body.String())
	}

	// Test JSON request
	reqJSON := httptest.NewRequest("GET", "/test", nil)
	reqJSON.Header.Set("Accept", "application/json")
	wJSON := httptest.NewRecorder()
	nextJSON := mockHandler{status: http.StatusInternalServerError}
	if err := g.ServeHTTP(wJSON, reqJSON, nextJSON); err != nil {
		t.Fatalf("ServeHTTP JSON failed: %v", err)
	}

	var jsonBody map[string]interface{}
	if err := json.Unmarshal(wJSON.Body.Bytes(), &jsonBody); err != nil {
		t.Fatalf("failed to parse custom JSON response: %v", err)
	}
	if cs, ok := jsonBody["custom_status"].(float64); !ok || int(cs) != 500 {
		t.Errorf("expected custom_status 500, got %v", jsonBody["custom_status"])
	}
	if trace, ok := jsonBody["trace"].(string); !ok || trace == "" {
		t.Errorf("expected trace ID, got %v", jsonBody["trace"])
	}
}

func TestErrorGate_InterceptJSON_ContentType(t *testing.T) {
	g := ErrorGate{
		MinStatus: 500,
		MaxStatus: 599,
	}
	if err := g.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	next := mockHandler{
		status: http.StatusInternalServerError,
	}

	err := g.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestErrorGate_UpstreamMessages(t *testing.T) {
	tests := []struct {
		name            string
		upstreamBody    string
		expectedMessage string
	}{
		{
			name:            "upstream msg key",
			upstreamBody:    `{"msg": "custom msg error"}`,
			expectedMessage: "custom msg error",
		},
		{
			name:            "upstream message key",
			upstreamBody:    `{"message": "custom message error"}`,
			expectedMessage: "custom message error",
		},
		{
			name:            "upstream detail key",
			upstreamBody:    `{"detail": "custom detail error"}`,
			expectedMessage: "custom detail error",
		},
		{
			name:            "upstream msg key precedence over detail",
			upstreamBody:    `{"detail": "custom detail error", "msg": "custom msg error"}`,
			expectedMessage: "custom msg error",
		},
		{
			name:            "no matching key",
			upstreamBody:    `{"other": "random error"}`,
			expectedMessage: "Internal Server Error",
		},
		{
			name:            "invalid json body",
			upstreamBody:    `invalid json`,
			expectedMessage: "Internal Server Error",
		},
		{
			name:            "empty body",
			upstreamBody:    ``,
			expectedMessage: "Internal Server Error",
		},
		{
			name:            "msg key with non-string type formatted",
			upstreamBody:    `{"msg": 4041}`,
			expectedMessage: "4041",
		},
		{
			name:            "msg with quotes needing escape",
			upstreamBody:    `{"msg": "error: \"something failed\""}`,
			expectedMessage: "error: \"something failed\"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := ErrorGate{
				MinStatus: 500,
				MaxStatus: 599,
			}
			if err := g.Provision(caddy.Context{}); err != nil {
				t.Fatalf("Provision failed: %v", err)
			}

			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()

			next := mockHandler{
				status: http.StatusInternalServerError,
				body:   tc.upstreamBody,
			}

			err := g.ServeHTTP(w, req, next)
			if err != nil {
				t.Fatalf("ServeHTTP failed: %v", err)
			}

			var jsonBody map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &jsonBody); err != nil {
				t.Fatalf("failed to parse JSON response: %v, raw: %s", err, w.Body.String())
			}

			msgVal, ok := jsonBody["message"].(string)
			if !ok {
				t.Fatalf("expected message to be a string, got %v", jsonBody["message"])
			}

			if msgVal != tc.expectedMessage {
				t.Errorf("expected message %q, got %q", tc.expectedMessage, msgVal)
			}
		})
	}
}

func TestErrorGate_I18n(t *testing.T) {
	tests := []struct {
		name           string
		acceptLang     string
		expectedSubstr string
	}{
		{"Chinese", "zh-CN,zh;q=0.9", "连接状态"},
		{"English", "en-US,en;q=0.8", "Connection status"},
		{"Arabic", "ar", "حالة الاتصال"},
		{"French", "fr;q=0.9", "Statut de la connexion"},
		{"Russian", "ru,en;q=0.5", "Статус подключения"},
		{"Spanish", "es-ES,es;q=0.9", "Estado de la conexión"},
		{"Fallback", "de-DE,de;q=0.9", "Connection status"},
	}

	g := ErrorGate{
		MinStatus: 500,
		MaxStatus: 599,
	}
	if err := g.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Accept-Language", tc.acceptLang)
			w := httptest.NewRecorder()

			next := mockHandler{
				status: http.StatusInternalServerError,
			}

			err := g.ServeHTTP(w, req, next)
			if err != nil {
				t.Fatalf("ServeHTTP failed: %v", err)
			}

			body := w.Body.String()
			if !strings.Contains(body, tc.expectedSubstr) {
				t.Errorf("expected HTML body to contain %q, but got body: %s", tc.expectedSubstr, body)
			}
		})
	}
}

func TestErrorGate_RequestIDPassthrough(t *testing.T) {
	t.Run("default candidate header in response", func(t *testing.T) {
		g := ErrorGate{MinStatus: 500, MaxStatus: 599}
		if err := g.Provision(caddy.Context{}); err != nil {
			t.Fatalf("Provision failed: %v", err)
		}
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		next := mockHandler{
			status: http.StatusInternalServerError,
			headers: http.Header{
				"Requestid": []string{"upstream-req-123"},
			},
		}
		if err := g.ServeHTTP(w, req, next); err != nil {
			t.Fatalf("ServeHTTP failed: %v", err)
		}
		if reqID := w.Header().Get("X-Catyuki-Req-Id"); reqID != "upstream-req-123" {
			t.Errorf("expected X-Catyuki-Req-Id 'upstream-req-123', got %q", reqID)
		}
		if origID := w.Header().Get("Requestid"); origID != "" {
			t.Errorf("expected original header Requestid to be stripped, got %q", origID)
		}
	})

	t.Run("custom configured header in response", func(t *testing.T) {
		g := ErrorGate{
			MinStatus:        500,
			MaxStatus:        599,
			RequestIDHeaders: []string{"X-Custom-Req-Id"},
		}
		if err := g.Provision(caddy.Context{}); err != nil {
			t.Fatalf("Provision failed: %v", err)
		}
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		next := mockHandler{
			status: http.StatusInternalServerError,
			headers: http.Header{
				"X-Custom-Req-Id": []string{"custom-val-789"},
			},
		}
		if err := g.ServeHTTP(w, req, next); err != nil {
			t.Fatalf("ServeHTTP failed: %v", err)
		}
		if reqID := w.Header().Get("X-Catyuki-Req-Id"); reqID != "custom-val-789" {
			t.Errorf("expected X-Catyuki-Req-Id 'custom-val-789', got %q", reqID)
		}
		if origID := w.Header().Get("X-Custom-Req-Id"); origID != "" {
			t.Errorf("expected original header X-Custom-Req-Id to be stripped, got %q", origID)
		}
	})

	t.Run("header in request", func(t *testing.T) {
		g := ErrorGate{MinStatus: 500, MaxStatus: 599}
		if err := g.Provision(caddy.Context{}); err != nil {
			t.Fatalf("Provision failed: %v", err)
		}
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("x-request-id", "client-req-abc")
		w := httptest.NewRecorder()
		next := mockHandler{
			status: http.StatusInternalServerError,
		}
		if err := g.ServeHTTP(w, req, next); err != nil {
			t.Fatalf("ServeHTTP failed: %v", err)
		}
		if reqID := w.Header().Get("X-Catyuki-Req-Id"); reqID != "client-req-abc" {
			t.Errorf("expected X-Catyuki-Req-Id 'client-req-abc', got %q", reqID)
		}
	})
}

func TestErrorGate_NonBrowserClients(t *testing.T) {
	g := ErrorGate{MinStatus: 500, MaxStatus: 599}
	if err := g.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	tests := []struct {
		name       string
		userAgent  string
		accept     string
		expectJSON bool
	}{
		{
			name:       "browser Chrome",
			userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			accept:     "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			expectJSON: false,
		},
		{
			name:       "curl client",
			userAgent:  "curl/7.64.1",
			accept:     "*/*",
			expectJSON: true,
		},
		{
			name:       "python requests",
			userAgent:  "python-requests/2.25.1",
			accept:     "*/*",
			expectJSON: true,
		},
		{
			name:       "go client",
			userAgent:  "Go-http-client/1.1",
			accept:     "",
			expectJSON: true,
		},
		{
			name:       "java okhttp",
			userAgent:  "okhttp/3.14.9",
			accept:     "",
			expectJSON: true,
		},
		{
			name:       "empty headers",
			userAgent:  "",
			accept:     "",
			expectJSON: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test-path", nil)
			if tc.userAgent != "" {
				req.Header.Set("User-Agent", tc.userAgent)
			}
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			w := httptest.NewRecorder()
			next := mockHandler{
				status: http.StatusInternalServerError,
				body:   "some upstream error body",
			}

			if err := g.ServeHTTP(w, req, next); err != nil {
				t.Fatalf("ServeHTTP failed: %v", err)
			}

			contentType := w.Header().Get("Content-Type")
			isJSON := strings.Contains(contentType, "application/json")
			if isJSON != tc.expectJSON {
				t.Errorf("expected isJSON to be %v, got %v (Content-Type: %q)", tc.expectJSON, isJSON, contentType)
			}
		})
	}
}

