package screeningapi

import (
	"net/http"

	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningapiv8d"
)

// Phase8DConfig is the policy-bound public screening API configuration.
type Phase8DConfig = screeningapiv8d.Config

// Phase8DServer is the scoring-integrated public front door over Phase 8B retrieval.
type Phase8DServer = screeningapiv8d.Server

// Phase8DUpstream abstracts the accepted Phase 8B retrieval API.
type Phase8DUpstream = screeningapiv8d.Upstream

func LoadPhase8DConfig(path string) (Phase8DConfig, error) {
	return screeningapiv8d.LoadConfig(path)
}

func NewPhase8DHTTPUpstream(baseURL string, client *http.Client) Phase8DUpstream {
	return screeningapiv8d.NewHTTPUpstream(baseURL, client)
}

func NewPhase8DServer(config Phase8DConfig, upstream Phase8DUpstream) (*Phase8DServer, error) {
	return screeningapiv8d.NewServer(config, upstream)
}

const Phase8DShutdownTimeout = screeningapiv8d.ShutdownTimeout
