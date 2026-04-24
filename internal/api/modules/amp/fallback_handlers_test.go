package amp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
)

func TestFallbackHandler_ModelMapping_PreservesThinkingSuffixAndRewritesResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reg := registry.GetGlobalRegistry()
	reg.RegisterClient("test-client-amp-fallback", "codex", []*registry.ModelInfo{
		{ID: "test/gpt-5.2", OwnedBy: "openai", Type: "codex"},
	})
	defer reg.UnregisterClient("test-client-amp-fallback")

	mapper := NewModelMapper([]config.AmpModelMapping{
		{From: "gpt-5.2", To: "test/gpt-5.2"},
	})

	fallback := NewFallbackHandlerWithMapper(func() *httputil.ReverseProxy { return nil }, mapper, nil)

	handler := func(c *gin.Context) {
		var req struct {
			Model string `json:"model"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"model":      req.Model,
			"seen_model": req.Model,
		})
	}

	r := gin.New()
	r.POST("/chat/completions", fallback.WrapHandler(handler))

	reqBody := []byte(`{"model":"gpt-5.2(xhigh)"}`)
	req := httptest.NewRequest(http.MethodPost, "/chat/completions", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	var resp struct {
		Model     string `json:"model"`
		SeenModel string `json:"seen_model"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response JSON: %v", err)
	}

	if resp.Model != "gpt-5.2(xhigh)" {
		t.Errorf("Expected response model gpt-5.2(xhigh), got %s", resp.Model)
	}
	if resp.SeenModel != "test/gpt-5.2(xhigh)" {
		t.Errorf("Expected handler to see test/gpt-5.2(xhigh), got %s", resp.SeenModel)
	}
}

// mockAuthChecker implements AuthAvailabilityChecker for testing.
type mockAuthChecker struct {
	available bool
}

func (m *mockAuthChecker) IsModelAvailable(provider, model string) bool {
	return m.available
}

func TestFallbackHandler_PreflightSkip_SkipsHandlerWhenAllAuthsExhausted(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reg := registry.GetGlobalRegistry()
	reg.RegisterClient("test-preflight-primary", "claude", []*registry.ModelInfo{
		{ID: "claude-opus-4-20250514", OwnedBy: "anthropic", Type: "claude"},
	})
	reg.RegisterClient("test-preflight-fallback", "codex", []*registry.ModelInfo{
		{ID: "test/gpt-5.4", OwnedBy: "openai", Type: "codex"},
	})
	defer reg.UnregisterClient("test-preflight-primary")
	defer reg.UnregisterClient("test-preflight-fallback")

	mapper := NewModelMapper([]config.AmpModelMapping{
		{From: "claude-opus-4-20250514", To: "test/gpt-5.4"},
	})

	fallback := NewFallbackHandlerWithMapper(func() *httputil.ReverseProxy { return nil }, mapper, nil)
	fallback.SetAuthChecker(&mockAuthChecker{available: false}) // All auths exhausted

	handlerCalls := 0
	handler := func(c *gin.Context) {
		handlerCalls++
		var req struct {
			Model string `json:"model"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"model":    req.Model,
			"fallback": true,
		})
	}

	r := gin.New()
	r.POST("/v1/messages", fallback.WrapHandler(handler))

	reqBody := []byte(`{"model":"claude-opus-4-20250514"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Handler should be called exactly once — for the fallback model only,
	// not for the primary (which was skipped via pre-flight check).
	if handlerCalls != 1 {
		t.Fatalf("Expected handler called 1 time (fallback only), got %d", handlerCalls)
	}

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp["fallback"] != true {
		t.Errorf("Expected fallback=true, got %v", resp)
	}
}

func TestFallbackHandler_PreflightSkip_DoesNotSkipWhenAuthsAvailable(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reg := registry.GetGlobalRegistry()
	reg.RegisterClient("test-preflight-avail", "claude", []*registry.ModelInfo{
		{ID: "claude-opus-4-20250514", OwnedBy: "anthropic", Type: "claude"},
	})
	defer reg.UnregisterClient("test-preflight-avail")

	fallback := NewFallbackHandler(func() *httputil.ReverseProxy { return nil })
	fallback.SetAuthChecker(&mockAuthChecker{available: true}) // Auths available

	handler := func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"primary": true})
	}

	r := gin.New()
	r.POST("/v1/messages", fallback.WrapHandler(handler))

	reqBody := []byte(`{"model":"claude-opus-4-20250514"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp["primary"] != true {
		t.Errorf("Expected primary=true (handler should have been called), got %v", resp)
	}
}

func TestFallbackHandler_CircuitBreaker_FallsBackOnModelCooldown(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reg := registry.GetGlobalRegistry()
	reg.RegisterClient("test-cb-primary", "claude", []*registry.ModelInfo{
		{ID: "claude-opus-4-20250514", OwnedBy: "anthropic", Type: "claude"},
	})
	reg.RegisterClient("test-cb-fallback", "codex", []*registry.ModelInfo{
		{ID: "test/gpt-5.4", OwnedBy: "openai", Type: "codex"},
	})
	defer reg.UnregisterClient("test-cb-primary")
	defer reg.UnregisterClient("test-cb-fallback")

	mapper := NewModelMapper([]config.AmpModelMapping{
		{From: "claude-opus-4-20250514", To: "test/gpt-5.4"},
	})
	fallback := NewFallbackHandlerWithMapper(func() *httputil.ReverseProxy { return nil }, mapper, nil)
	// No auth checker — tests the reactive (post-handler) circuit breaker path

	callCount := 0
	handler := func(c *gin.Context) {
		callCount++
		if callCount == 1 {
			c.Status(http.StatusTooManyRequests)
			_, _ = c.Writer.Write([]byte(`{"error":{"code":"model_cooldown","message":"all auths exhausted"}}`))
			return
		}
		var req struct {
			Model string `json:"model"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"model": req.Model, "fallback": true})
	}

	r := gin.New()
	r.POST("/v1/messages", fallback.WrapHandler(handler))

	reqBody := []byte(`{"model":"claude-opus-4-20250514"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if callCount != 2 {
		t.Fatalf("Expected 2 handler calls (primary 429 + fallback), got %d", callCount)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}
