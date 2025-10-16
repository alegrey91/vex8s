package llm

import (
	"context"
	"fmt"

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/anthropic"
	"github.com/tmc/langchaingo/llms/googleai"
	"github.com/tmc/langchaingo/llms/ollama"
)

const (
	Ollama    = "ollama"
	Anthropic = "anthropic"
	GoogleAI  = "googleai"
)

func New(ctx context.Context, name string, model string, url string, apiKey string) (llms.Model, error) {
	switch name {
	case Ollama:
		return ollama.New(
			ollama.WithModel(model),
			ollama.WithServerURL(url),
			ollama.WithFormat("json"),
		)
	case Anthropic:
		return anthropic.New(
			anthropic.WithModel(model),
			anthropic.WithToken(apiKey),
		)
	case GoogleAI:
		return googleai.New(
			ctx,
			googleai.WithAPIKey(apiKey),
			googleai.WithDefaultModel(model),
		)
	default:
		return nil, fmt.Errorf("unknown LLM")
	}
}
