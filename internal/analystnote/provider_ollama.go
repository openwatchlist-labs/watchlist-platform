package analystnote

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type OllamaProvider struct {
	baseURL string
	modelID string
	client  *http.Client
}

func NewOllamaProvider(baseURL, modelID string, timeout time.Duration) *OllamaProvider {
	return &OllamaProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		modelID: modelID,
		client:  &http.Client{Timeout: timeout},
	}
}

func (p *OllamaProvider) Name() string    { return "ollama" }
func (p *OllamaProvider) ModelID() string { return p.modelID }

func (p *OllamaProvider) Draft(prompt string, schema map[string]any) ([]byte, error) {
	request := map[string]any{
		"model":    p.modelID,
		"messages": []map[string]string{{"role": "user", "content": prompt}},
		"stream":   false,
		"format":   schema,
		"options":  map[string]any{"temperature": 0},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequest(http.MethodPost, p.baseURL+"/api/chat", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("ollama status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var envelope struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	if strings.TrimSpace(envelope.Message.Content) == "" {
		return nil, fmt.Errorf("ollama returned empty message content")
	}
	return []byte(envelope.Message.Content), nil
}
