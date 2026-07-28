package assistancerag

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ModelRequest struct {
	Model         string
	Messages      []Message
	ContextTokens int
	KeepAlive     string
}

type ModelResponse struct {
	Content         string
	DurationNanos   int64
	PromptTokens    int
	GeneratedTokens int
}

type ModelClient interface {
	Generate(context.Context, ModelRequest) (ModelResponse, error)
	ListModels(context.Context) ([]string, error)
}

type OllamaClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewOllamaClient(baseURL string, timeout time.Duration) *OllamaClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "http://127.0.0.1:11434"
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &OllamaClient{BaseURL: strings.TrimRight(baseURL, "/"), HTTPClient: &http.Client{Timeout: timeout}}
}

func (c *OllamaClient) Generate(ctx context.Context, request ModelRequest) (ModelResponse, error) {
	body := map[string]any{
		"model": request.Model, "messages": request.Messages, "stream": false, "format": "json",
		"keep_alive": request.KeepAlive, "options": map[string]any{"num_ctx": request.ContextTokens, "temperature": 0},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return ModelResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/chat", bytes.NewReader(raw))
	if err != nil {
		return ModelResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return ModelResponse{}, err
	}
	defer resp.Body.Close()
	limited, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return ModelResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return ModelResponse{}, fmt.Errorf("ollama status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	var envelope struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		TotalDuration   int64  `json:"total_duration"`
		PromptEvalCount int    `json:"prompt_eval_count"`
		EvalCount       int    `json:"eval_count"`
		Error           string `json:"error"`
	}
	if err := json.Unmarshal(limited, &envelope); err != nil {
		return ModelResponse{}, err
	}
	if envelope.Error != "" {
		return ModelResponse{}, errors.New(envelope.Error)
	}
	if strings.TrimSpace(envelope.Message.Content) == "" {
		return ModelResponse{}, errors.New("ollama returned empty content")
	}
	return ModelResponse{Content: envelope.Message.Content, DurationNanos: envelope.TotalDuration, PromptTokens: envelope.PromptEvalCount, GeneratedTokens: envelope.EvalCount}, nil
}

func (c *OllamaClient) ListModels(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/tags", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama tags status %d", resp.StatusCode)
	}
	var envelope struct {
		Models []struct {
			Name  string `json:"name"`
			Model string `json:"model"`
		} `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&envelope); err != nil {
		return nil, err
	}
	var out []string
	for _, m := range envelope.Models {
		if m.Name != "" {
			out = append(out, m.Name)
		} else if m.Model != "" {
			out = append(out, m.Model)
		}
	}
	sort.Strings(out)
	return out, nil
}

type FixtureModelClient struct {
	Responses map[string]ModelResponse
	Errors    map[string]error
	Models    []string
}

func (f *FixtureModelClient) Generate(_ context.Context, request ModelRequest) (ModelResponse, error) {
	if err := f.Errors[request.Model]; err != nil {
		return ModelResponse{}, err
	}
	response, ok := f.Responses[request.Model]
	if !ok {
		return ModelResponse{}, fmt.Errorf("fixture response is not configured for %s", request.Model)
	}
	return response, nil
}
func (f *FixtureModelClient) ListModels(context.Context) ([]string, error) {
	out := append([]string(nil), f.Models...)
	sort.Strings(out)
	return out, nil
}

func LoadFixtureModelClient(path string) (*FixtureModelClient, error) {
	var raw struct {
		Models    []string          `json:"models"`
		Responses map[string]string `json:"responses"`
		Errors    map[string]string `json:"errors"`
	}
	if err := ReadStrictJSON(path, &raw); err != nil {
		return nil, err
	}
	client := &FixtureModelClient{Responses: map[string]ModelResponse{}, Errors: map[string]error{}, Models: raw.Models}
	for model, content := range raw.Responses {
		client.Responses[model] = ModelResponse{Content: content, DurationNanos: 1000000, PromptTokens: 128, GeneratedTokens: 64}
	}
	for model, message := range raw.Errors {
		client.Errors[model] = errors.New(message)
	}
	return client, nil
}
