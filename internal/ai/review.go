package ai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
)

const (
	StatusSkipped     = "skipped"
	StatusSuccess     = "success"
	StatusCached      = "cached"
	StatusError       = "error"
	StatusTimeout     = "timeout"
	StatusCircuitOpen = "circuit_open"

	ActionReview           = "review"
	ActionAllow            = "allow"
	ActionWarn             = "warn"
	ActionBlockRecommended = "block_recommended"

	defaultTemplateVersion = "phase14-default-v1"
	defaultSystemTemplate  = "You are an auxiliary content moderation reviewer for OpenAudit. The deterministic rule engine is authoritative. Return only compact JSON matching the requested schema. Prefer action=review for ambiguous or AI-only concerns; do not claim that AI alone has blocked content."
	defaultUserTemplate    = `Review this content as a supplementary layer.

Text excerpt:
{{.TextExcerpt}}

Deterministic rule result:
action={{.RuleAction}}
risk_score={{.RiskScore}}
matched={{.Matched}}

Rule hits JSON:
{{.RuleHitsJSON}}

Requested JSON schema:
{"action":"review|allow|warn|block_recommended","confidence":0.0,"risk_level":"low|medium|high|critical","category":"string","explanation":"string","reasons":["string"]}`
)

type Provider interface {
	Name() string
	Review(ctx context.Context, req ReviewRequest) (ReviewResult, error)
	Health(ctx context.Context) error
}

type ReviewRequest struct {
	RequestID       string
	Provider        string
	Model           string
	TextExcerpt     string
	RuleAction      string
	RiskScore       int
	Matched         bool
	RuleHits        []RuleHitContext
	SystemPrompt    string
	UserPrompt      string
	TemplateVersion string
}

type RuleHitContext struct {
	Type        string `json:"type,omitempty"`
	VariantType string `json:"variant_type,omitempty"`
	RuleID      string `json:"rule_id,omitempty"`
	Category    string `json:"category,omitempty"`
	RiskLevel   string `json:"risk_level,omitempty"`
	Action      string `json:"action,omitempty"`
	Score       int    `json:"score,omitempty"`
}

type ReviewResult struct {
	Enabled       bool
	RequestID     string
	Provider      string
	Model         string
	Status        string
	Action        string
	Confidence    float64
	RiskLevel     string
	Category      string
	Explanation   string
	Reasons       []string
	CacheHit      bool
	LatencyMS     int64
	TokenUsage    TokenUsage
	EstimatedCost float64
	ErrorClass    string
	Error         string
	Metadata      map[string]any
}

type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens,omitempty"`
	CompletionTokens int `json:"completion_tokens,omitempty"`
	TotalTokens      int `json:"total_tokens,omitempty"`
}

type AuditLog struct {
	RequestID        string
	CreatedAt        time.Time
	Provider         string
	Model            string
	Status           string
	Action           string
	Confidence       float64
	RiskLevel        string
	Category         string
	LatencyMS        int64
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	EstimatedCost    float64
	CacheHit         bool
	ErrorClass       string
	MetadataJSON     string
}

type AuditLogger interface {
	InsertAIReviewLog(context.Context, AuditLog) error
}

type Service struct {
	cfg      config.AIConfig
	provs    map[string]Provider
	cache    *MemoryCache
	breakers map[string]*CircuitBreaker
	logger   AuditLogger
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
}

func NewService(cfg config.AIConfig, logger AuditLogger) *Service {
	return NewServiceWithProviders(cfg, logger, BuildProviders(cfg))
}

func NewServiceWithProviders(cfg config.AIConfig, logger AuditLogger, providers map[string]Provider) *Service {
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = ActionReview
	}
	if cfg.TimeoutMS <= 0 {
		cfg.TimeoutMS = 8000
	}
	if cfg.RetryBackoffMS <= 0 {
		cfg.RetryBackoffMS = 250
	}
	if cfg.CircuitBreakerFailureThreshold <= 0 {
		cfg.CircuitBreakerFailureThreshold = 5
	}
	if cfg.CircuitBreakerCooldownMS <= 0 {
		cfg.CircuitBreakerCooldownMS = 30000
	}
	if cfg.MaxExcerptRunes <= 0 {
		cfg.MaxExcerptRunes = 2000
	}
	if cfg.Cache.TTLSeconds <= 0 {
		cfg.Cache.TTLSeconds = 3600
	}
	s := &Service{cfg: cfg, provs: providers, cache: NewMemoryCache(), breakers: map[string]*CircuitBreaker{}, logger: logger, now: func() time.Time { return time.Now().UTC() }, sleep: sleepContext}
	for name := range providers {
		s.breakers[name] = NewCircuitBreaker(cfg.CircuitBreakerFailureThreshold, time.Duration(cfg.CircuitBreakerCooldownMS)*time.Millisecond)
	}
	return s
}

func (s *Service) Enabled() bool {
	return s != nil && s.cfg.Enabled
}

func (s *Service) Review(ctx context.Context, text string, deterministic engine.Result) ReviewResult {
	if s == nil || !s.cfg.Enabled {
		return ReviewResult{Enabled: false, Status: StatusSkipped, Action: ActionReview}
	}
	start := s.now()
	providerName := strings.TrimSpace(s.cfg.Provider)
	if providerName == "" {
		providerName = "openai"
	}
	prov := s.provs[providerName]
	if prov == nil {
		return s.finish(ctx, start, ReviewResult{Enabled: true, Provider: providerName, Model: s.modelFor(providerName), Status: StatusSkipped, Action: ActionReview, ErrorClass: "provider_unconfigured", Error: "AI provider is not configured"})
	}
	req, err := s.buildRequest(providerName, text, deterministic)
	if err != nil {
		return s.finish(ctx, start, ReviewResult{Enabled: true, Provider: providerName, Model: s.modelFor(providerName), Status: StatusError, Action: ActionReview, ErrorClass: "prompt_error", Error: err.Error()})
	}
	key := CacheKey(req, s.cfg)
	if s.cfg.Cache.Enabled {
		if cached, ok := s.cache.Get(key, s.now()); ok {
			cached.CacheHit = true
			cached.Status = StatusCached
			cached.LatencyMS = sinceMS(start, s.now())
			return s.finish(ctx, start, cached)
		}
	}
	br := s.breakers[providerName]
	if br != nil && !br.Allow(s.now()) {
		return s.finish(ctx, start, ReviewResult{Enabled: true, RequestID: req.RequestID, Provider: providerName, Model: req.Model, Status: StatusCircuitOpen, Action: ActionReview, ErrorClass: "circuit_open", Error: "AI provider circuit breaker is open"})
	}
	result, err := s.callWithRetry(ctx, prov, req)
	if err != nil {
		if br != nil {
			br.RecordFailure(s.now())
		}
		result = providerFailureResult(req, err)
		result.LatencyMS = sinceMS(start, s.now())
		return s.finish(ctx, start, result)
	}
	if br != nil {
		br.RecordSuccess()
	}
	result.Enabled = true
	result.RequestID = req.RequestID
	result.Provider = providerName
	result.Model = req.Model
	result.Status = StatusSuccess
	result.Action = normalizeAction(result.Action, s.cfg.HardBlockEnabled)
	result.Confidence = clamp(result.Confidence, 0, 1)
	result.LatencyMS = sinceMS(start, s.now())
	if s.cfg.CostTracking.Enabled {
		result.EstimatedCost = EstimateCost(result.TokenUsage, s.providerConfig(providerName))
	}
	if s.cfg.Cache.Enabled {
		s.cache.Set(key, result, s.now().Add(time.Duration(s.cfg.Cache.TTLSeconds)*time.Second))
	}
	return s.finish(ctx, start, result)
}

func (s *Service) buildRequest(providerName, text string, deterministic engine.Result) (ReviewRequest, error) {
	hits := make([]RuleHitContext, 0, len(deterministic.Hits))
	for _, h := range deterministic.Hits {
		hits = append(hits, RuleHitContext{Type: h.Type, VariantType: h.VariantType, RuleID: h.RuleID, Category: h.Category, RiskLevel: h.RiskLevel, Action: h.Action, Score: h.Score})
	}
	req := ReviewRequest{RequestID: fmt.Sprintf("ai_%d", s.now().UnixNano()), Provider: providerName, Model: s.modelFor(providerName), TextExcerpt: excerptRunes(text, s.cfg.MaxExcerptRunes), RuleAction: deterministic.Action, RiskScore: deterministic.RiskScore, Matched: deterministic.Matched, RuleHits: hits, TemplateVersion: templateVersion(s.cfg)}
	p, err := RenderPrompt(s.cfg, req)
	if err != nil {
		return req, err
	}
	req.SystemPrompt = p.System
	req.UserPrompt = p.User
	return req, nil
}

func (s *Service) callWithRetry(ctx context.Context, prov Provider, req ReviewRequest) (ReviewResult, error) {
	attempts := s.cfg.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	var last error
	for i := 0; i < attempts; i++ {
		callCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.TimeoutMS)*time.Millisecond)
		res, err := prov.Review(callCtx, req)
		cancel()
		if err == nil {
			return res, nil
		}
		last = err
		if i == attempts-1 || !isTransient(err) {
			break
		}
		backoff := time.Duration(s.cfg.RetryBackoffMS) * time.Millisecond * time.Duration(1<<i)
		if err := s.sleep(ctx, backoff); err != nil {
			return ReviewResult{}, err
		}
	}
	return ReviewResult{}, last
}

func (s *Service) finish(ctx context.Context, start time.Time, r ReviewResult) ReviewResult {
	if r.LatencyMS == 0 {
		r.LatencyMS = sinceMS(start, s.now())
	}
	if r.Action == "" {
		r.Action = ActionReview
	}
	if s.cfg.AuditLogs.Enabled && s.logger != nil && r.Enabled {
		meta := map[string]any{}
		if r.Metadata != nil {
			meta = r.Metadata
		}
		if !s.cfg.AuditLogs.StorePrompts && !s.cfg.AuditLogs.StoreRawResponse {
			delete(meta, "prompt")
			delete(meta, "raw_response")
		}
		b, _ := json.Marshal(meta)
		_ = s.logger.InsertAIReviewLog(ctx, AuditLog{RequestID: r.RequestID, CreatedAt: s.now(), Provider: r.Provider, Model: r.Model, Status: r.Status, Action: r.Action, Confidence: r.Confidence, RiskLevel: r.RiskLevel, Category: r.Category, LatencyMS: r.LatencyMS, PromptTokens: r.TokenUsage.PromptTokens, CompletionTokens: r.TokenUsage.CompletionTokens, TotalTokens: r.TokenUsage.TotalTokens, EstimatedCost: r.EstimatedCost, CacheHit: r.CacheHit, ErrorClass: r.ErrorClass, MetadataJSON: string(b)})
	}
	return r
}

func (s *Service) modelFor(provider string) string {
	if s.cfg.Model != "" {
		return s.cfg.Model
	}
	return s.providerConfig(provider).Model
}

func (s *Service) providerConfig(provider string) config.AIProviderConfig {
	switch provider {
	case "openai":
		return s.cfg.Providers.OpenAI
	case "deepseek":
		return s.cfg.Providers.DeepSeek
	case "qwen":
		return s.cfg.Providers.Qwen
	case "gemini":
		return s.cfg.Providers.Gemini
	case "claude":
		return s.cfg.Providers.Claude
	case "local":
		return s.cfg.Providers.Local
	default:
		return config.AIProviderConfig{}
	}
}

type RenderedPrompt struct {
	System string
	User   string
}

func RenderPrompt(cfg config.AIConfig, req ReviewRequest) (RenderedPrompt, error) {
	systemT := strings.TrimSpace(cfg.Prompt.SystemTemplate)
	if systemT == "" {
		systemT = defaultSystemTemplate
	}
	userT := strings.TrimSpace(cfg.Prompt.UserTemplate)
	if userT == "" {
		userT = defaultUserTemplate
	}
	hits, _ := json.Marshal(req.RuleHits)
	data := struct {
		TextExcerpt  string
		RuleAction   string
		RiskScore    int
		Matched      bool
		RuleHits     []RuleHitContext
		RuleHitsJSON string
	}{
		TextExcerpt:  req.TextExcerpt,
		RuleAction:   req.RuleAction,
		RiskScore:    req.RiskScore,
		Matched:      req.Matched,
		RuleHits:     req.RuleHits,
		RuleHitsJSON: string(hits),
	}
	system, err := renderTemplate("ai.system", systemT, data)
	if err != nil {
		return RenderedPrompt{}, err
	}
	user, err := renderTemplate("ai.user", userT, data)
	if err != nil {
		return RenderedPrompt{}, err
	}
	return RenderedPrompt{System: system, User: user}, nil
}

func renderTemplate(name, body string, data any) (string, error) {
	t, err := template.New(name).Option("missingkey=error").Parse(body)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func CacheKey(req ReviewRequest, cfg config.AIConfig) string {
	h := sha256.New()
	writeHashPart(h, req.Provider)
	writeHashPart(h, req.Model)
	writeHashPart(h, req.TemplateVersion)
	writeHashPart(h, sha256Hex(req.TextExcerpt))
	ctx := struct {
		Action        string
		RiskScore     int
		Matched       bool
		Hits          []RuleHitContext
		DefaultAction string
		HardBlock     bool
	}{req.RuleAction, req.RiskScore, req.Matched, req.RuleHits, cfg.DefaultAction, cfg.HardBlockEnabled}
	b, _ := json.Marshal(ctx)
	writeHashPart(h, string(b))
	return hex.EncodeToString(h.Sum(nil))
}

func writeHashPart(w io.Writer, s string) {
	_, _ = io.WriteString(w, s)
	_, _ = io.WriteString(w, "\x00")
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type cacheEntry struct {
	Result    ReviewResult
	ExpiresAt time.Time
}

type MemoryCache struct {
	mu sync.Mutex
	m  map[string]cacheEntry
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{m: map[string]cacheEntry{}}
}

func (c *MemoryCache) Get(key string, now time.Time) (ReviewResult, bool) {
	if c == nil {
		return ReviewResult{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return ReviewResult{}, false
	}
	if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
		delete(c.m, key)
		return ReviewResult{}, false
	}
	return e.Result, true
}

func (c *MemoryCache) Set(key string, r ReviewResult, expires time.Time) {
	if c == nil {
		return
	}
	r.CacheHit = false
	c.mu.Lock()
	c.m[key] = cacheEntry{Result: r, ExpiresAt: expires}
	c.mu.Unlock()
}

type CircuitBreaker struct {
	mu          sync.Mutex
	threshold   int
	cooldown    time.Duration
	failures    int
	openedUntil time.Time
	halfOpen    bool
}

func NewCircuitBreaker(threshold int, cooldown time.Duration) *CircuitBreaker {
	if threshold <= 0 {
		threshold = 5
	}
	return &CircuitBreaker{threshold: threshold, cooldown: cooldown}
}

func (b *CircuitBreaker) Allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openedUntil.IsZero() || now.After(b.openedUntil) {
		if !b.openedUntil.IsZero() {
			b.halfOpen = true
		}
		return true
	}
	return false
}

func (b *CircuitBreaker) RecordSuccess() {
	b.mu.Lock()
	b.failures = 0
	b.openedUntil = time.Time{}
	b.halfOpen = false
	b.mu.Unlock()
}

func (b *CircuitBreaker) RecordFailure(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.halfOpen {
		b.failures = b.threshold
	} else {
		b.failures++
	}
	if b.failures >= b.threshold {
		b.openedUntil = now.Add(b.cooldown)
		b.halfOpen = false
	}
}

func EstimateCost(u TokenUsage, pc config.AIProviderConfig) float64 {
	if u.PromptTokens == 0 && u.CompletionTokens == 0 && u.TotalTokens == 0 {
		return 0
	}
	return float64(u.PromptTokens)/1000*pc.InputCostPer1K + float64(u.CompletionTokens)/1000*pc.OutputCostPer1K
}

func ToEngineReview(r ReviewResult) *engine.AIReview {
	return &engine.AIReview{Enabled: r.Enabled, RequestID: r.RequestID, Provider: r.Provider, Model: r.Model, Status: r.Status, Action: r.Action, Confidence: r.Confidence, RiskLevel: r.RiskLevel, Category: r.Category, Explanation: r.Explanation, Reasons: r.Reasons, CacheHit: r.CacheHit, LatencyMS: r.LatencyMS, TokenUsage: engine.TokenUsage{PromptTokens: r.TokenUsage.PromptTokens, CompletionTokens: r.TokenUsage.CompletionTokens, TotalTokens: r.TokenUsage.TotalTokens}, EstimatedCost: r.EstimatedCost, ErrorClass: r.ErrorClass, Error: r.Error}
}

func providerFailureResult(req ReviewRequest, err error) ReviewResult {
	status := StatusError
	class := "provider_error"
	if errors.Is(err, context.DeadlineExceeded) {
		status = StatusTimeout
		class = "timeout"
	}
	var pe ProviderError
	if errors.As(err, &pe) {
		class = pe.Class
		if pe.Timeout {
			status = StatusTimeout
		}
	}
	return ReviewResult{Enabled: true, RequestID: req.RequestID, Provider: req.Provider, Model: req.Model, Status: status, Action: ActionReview, ErrorClass: class, Error: safeError(err)}
}

func normalizeAction(action string, allowHardBlock bool) string {
	switch strings.TrimSpace(strings.ToLower(action)) {
	case ActionAllow:
		return ActionAllow
	case ActionWarn:
		return ActionWarn
	case "block", ActionBlockRecommended:
		if allowHardBlock && action == "block" {
			return "block"
		}
		return ActionBlockRecommended
	case ActionReview, "":
		return ActionReview
	default:
		return ActionReview
	}
}

func clamp(v, lo, hi float64) float64 {
	if math.IsNaN(v) {
		return 0
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func excerptRunes(s string, max int) string {
	rs := []rune(s)
	if max <= 0 || len(rs) <= max {
		return s
	}
	return string(rs[:max])
}

func templateVersion(cfg config.AIConfig) string {
	if strings.TrimSpace(cfg.Prompt.Version) != "" {
		return cfg.Prompt.Version
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(cfg.Prompt.SystemTemplate) + "\x00" + strings.TrimSpace(cfg.Prompt.UserTemplate)))
	if strings.TrimSpace(cfg.Prompt.SystemTemplate) == "" && strings.TrimSpace(cfg.Prompt.UserTemplate) == "" {
		return defaultTemplateVersion
	}
	return hex.EncodeToString(sum[:])
}

func sinceMS(start, now time.Time) int64 {
	if now.Before(start) {
		return 0
	}
	return now.Sub(start).Milliseconds()
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func isTransient(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var pe ProviderError
	if errors.As(err, &pe) {
		return pe.Transient
	}
	return false
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, env := range []string{"OPENAI_API_KEY", "DEEPSEEK_API_KEY", "QWEN_API_KEY", "GEMINI_API_KEY", "ANTHROPIC_API_KEY"} {
		if v := os.Getenv(env); v != "" {
			msg = strings.ReplaceAll(msg, v, "[redacted]")
		}
	}
	return msg
}

type ProviderError struct {
	Class     string
	Message   string
	Status    int
	Transient bool
	Timeout   bool
}

func (e ProviderError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("%s: HTTP %d", e.Message, e.Status)
	}
	return e.Message
}

type schemaResult struct {
	Action      string   `json:"action"`
	Confidence  float64  `json:"confidence"`
	RiskLevel   string   `json:"risk_level"`
	Category    string   `json:"category"`
	Explanation string   `json:"explanation"`
	Reasons     []string `json:"reasons"`
}

func resultFromJSON(content string) (ReviewResult, error) {
	var sr schemaResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(content)), &sr); err != nil {
		return ReviewResult{}, ProviderError{Class: "invalid_response", Message: "provider returned non-JSON review"}
	}
	return ReviewResult{Action: sr.Action, Confidence: sr.Confidence, RiskLevel: sr.RiskLevel, Category: sr.Category, Explanation: sr.Explanation, Reasons: sr.Reasons}, nil
}

func BuildProviders(cfg config.AIConfig) map[string]Provider {
	out := map[string]Provider{}
	addOpenAICompatible := func(name string, pc config.AIProviderConfig, defaultBase string) {
		if !pc.Enabled {
			return
		}
		key := strings.TrimSpace(os.Getenv(pc.APIKeyEnv))
		if key == "" && name != "local" {
			return
		}
		base := pc.BaseURL
		if base == "" {
			base = defaultBase
		}
		out[name] = NewOpenAICompatibleProvider(name, base, key, pc.Model)
	}
	addOpenAICompatible("openai", cfg.Providers.OpenAI, "https://api.openai.com/v1")
	addOpenAICompatible("deepseek", cfg.Providers.DeepSeek, "https://api.deepseek.com")
	addOpenAICompatible("qwen", cfg.Providers.Qwen, "https://dashscope-intl.aliyuncs.com/compatible-mode/v1")
	addOpenAICompatible("local", cfg.Providers.Local, "http://127.0.0.1:11434/v1")
	if cfg.Providers.Gemini.Enabled {
		if key := strings.TrimSpace(os.Getenv(cfg.Providers.Gemini.APIKeyEnv)); key != "" {
			out["gemini"] = NewGeminiProvider(cfg.Providers.Gemini.BaseURL, key, cfg.Providers.Gemini.Model)
		}
	}
	if cfg.Providers.Claude.Enabled {
		if key := strings.TrimSpace(os.Getenv(cfg.Providers.Claude.APIKeyEnv)); key != "" {
			out["claude"] = NewClaudeProvider(cfg.Providers.Claude.BaseURL, key, cfg.Providers.Claude.Model)
		}
	}
	return out
}

type OpenAICompatibleProvider struct {
	name, baseURL, apiKey, model string
	client                       *http.Client
}

func NewOpenAICompatibleProvider(name, baseURL, apiKey, model string) *OpenAICompatibleProvider {
	return &OpenAICompatibleProvider{name: name, baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, model: model, client: &http.Client{}}
}

func (p *OpenAICompatibleProvider) Name() string { return p.name }
func (p *OpenAICompatibleProvider) Health(context.Context) error {
	if p.name != "local" && strings.TrimSpace(p.apiKey) == "" {
		return ProviderError{Class: "missing_api_key", Message: "provider API key is not configured"}
	}
	return nil
}
func (p *OpenAICompatibleProvider) Review(ctx context.Context, req ReviewRequest) (ReviewResult, error) {
	if err := p.Health(ctx); err != nil {
		return ReviewResult{}, err
	}
	body := map[string]any{"model": first(req.Model, p.model), "messages": []map[string]string{{"role": "system", "content": req.SystemPrompt}, {"role": "user", "content": req.UserPrompt}}, "response_format": map[string]string{"type": "json_object"}}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := p.postJSON(ctx, "/chat/completions", body, &parsed); err != nil {
		return ReviewResult{}, err
	}
	if len(parsed.Choices) == 0 {
		return ReviewResult{}, ProviderError{Class: "invalid_response", Message: "provider returned no choices"}
	}
	res, err := resultFromJSON(parsed.Choices[0].Message.Content)
	if err != nil {
		return ReviewResult{}, err
	}
	res.TokenUsage = TokenUsage{PromptTokens: parsed.Usage.PromptTokens, CompletionTokens: parsed.Usage.CompletionTokens, TotalTokens: parsed.Usage.TotalTokens}
	return res, nil
}

func (p *OpenAICompatibleProvider) postJSON(ctx context.Context, path string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	u := p.baseURL + path
	if strings.HasSuffix(p.baseURL, "/chat/completions") {
		u = p.baseURL
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	return doJSON(p.client, httpReq, out)
}

type GeminiProvider struct {
	baseURL, apiKey, model string
	client                 *http.Client
}

func NewGeminiProvider(baseURL, apiKey, model string) *GeminiProvider {
	if baseURL == "" {
		baseURL = "https://generativelanguage.googleapis.com/v1beta"
	}
	return &GeminiProvider{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, model: model, client: &http.Client{}}
}
func (p *GeminiProvider) Name() string { return "gemini" }
func (p *GeminiProvider) Health(context.Context) error {
	if strings.TrimSpace(p.apiKey) == "" {
		return ProviderError{Class: "missing_api_key", Message: "provider API key is not configured"}
	}
	return nil
}
func (p *GeminiProvider) Review(ctx context.Context, req ReviewRequest) (ReviewResult, error) {
	if err := p.Health(ctx); err != nil {
		return ReviewResult{}, err
	}
	body := map[string]any{"systemInstruction": map[string]any{"parts": []map[string]string{{"text": req.SystemPrompt}}}, "contents": []map[string]any{{"role": "user", "parts": []map[string]string{{"text": req.UserPrompt}}}}, "generationConfig": map[string]string{"responseMimeType": "application/json"}}
	var parsed struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		UsageMetadata struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
			TotalTokenCount      int `json:"totalTokenCount"`
		} `json:"usageMetadata"`
	}
	model := url.PathEscape(first(req.Model, p.model))
	u := fmt.Sprintf("%s/models/%s:generateContent?key=%s", p.baseURL, model, url.QueryEscape(p.apiKey))
	b, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return ReviewResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := doJSON(p.client, httpReq, &parsed); err != nil {
		return ReviewResult{}, err
	}
	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return ReviewResult{}, ProviderError{Class: "invalid_response", Message: "provider returned no candidates"}
	}
	res, err := resultFromJSON(parsed.Candidates[0].Content.Parts[0].Text)
	if err != nil {
		return ReviewResult{}, err
	}
	res.TokenUsage = TokenUsage{PromptTokens: parsed.UsageMetadata.PromptTokenCount, CompletionTokens: parsed.UsageMetadata.CandidatesTokenCount, TotalTokens: parsed.UsageMetadata.TotalTokenCount}
	return res, nil
}

type ClaudeProvider struct {
	baseURL, apiKey, model string
	client                 *http.Client
}

func NewClaudeProvider(baseURL, apiKey, model string) *ClaudeProvider {
	if baseURL == "" {
		baseURL = "https://api.anthropic.com/v1"
	}
	return &ClaudeProvider{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, model: model, client: &http.Client{}}
}
func (p *ClaudeProvider) Name() string { return "claude" }
func (p *ClaudeProvider) Health(context.Context) error {
	if strings.TrimSpace(p.apiKey) == "" {
		return ProviderError{Class: "missing_api_key", Message: "provider API key is not configured"}
	}
	return nil
}
func (p *ClaudeProvider) Review(ctx context.Context, req ReviewRequest) (ReviewResult, error) {
	if err := p.Health(ctx); err != nil {
		return ReviewResult{}, err
	}
	body := map[string]any{"model": first(req.Model, p.model), "max_tokens": 600, "system": req.SystemPrompt, "messages": []map[string]string{{"role": "user", "content": req.UserPrompt}}}
	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	b, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/messages", bytes.NewReader(b))
	if err != nil {
		return ReviewResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	if err := doJSON(p.client, httpReq, &parsed); err != nil {
		return ReviewResult{}, err
	}
	for _, c := range parsed.Content {
		if c.Text != "" {
			res, err := resultFromJSON(c.Text)
			if err != nil {
				return ReviewResult{}, err
			}
			res.TokenUsage = TokenUsage{PromptTokens: parsed.Usage.InputTokens, CompletionTokens: parsed.Usage.OutputTokens, TotalTokens: parsed.Usage.InputTokens + parsed.Usage.OutputTokens}
			return res, nil
		}
	}
	return ReviewResult{}, ProviderError{Class: "invalid_response", Message: "provider returned no text content"}
}

func doJSON(client *http.Client, req *http.Request, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(req.Context().Err(), context.DeadlineExceeded) {
			return ProviderError{Class: "timeout", Message: "provider request timed out", Transient: true, Timeout: true}
		}
		return ProviderError{Class: "network_error", Message: "provider request failed", Transient: true}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ProviderError{Class: "http_error", Message: "provider returned an error", Status: resp.StatusCode, Transient: resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500}
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := dec.Decode(out); err != nil {
		return ProviderError{Class: "invalid_response", Message: "provider returned invalid JSON"}
	}
	return nil
}

func first(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
