package screeningapi

import "github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"

// Phase8CCandidateScorer is a typed bridge to the candidatescoring engine.
// Its caller is ScoringBinding (scoring.go), held once at Service startup
// and used from screenAt() for both single and batch screening (DOM-3,
// ADR-0004 §4).
type Phase8CCandidateScorer struct {
	engine *candidatescoring.Engine
}

func LoadPhase8CCandidateScorer(policyPath string) (*Phase8CCandidateScorer, error) {
	policy, err := candidatescoring.LoadPolicy(policyPath)
	if err != nil {
		return nil, err
	}
	engine, err := candidatescoring.NewEngine(policy)
	if err != nil {
		return nil, err
	}
	return &Phase8CCandidateScorer{engine: engine}, nil
}

func NewPhase8CCandidateScorer(engine *candidatescoring.Engine) *Phase8CCandidateScorer {
	return &Phase8CCandidateScorer{engine: engine}
}

func (s *Phase8CCandidateScorer) Score(request candidatescoring.Request) (candidatescoring.Response, error) {
	return s.engine.Score(request)
}

func (s *Phase8CCandidateScorer) ScoreBatch(request candidatescoring.BatchRequest) (candidatescoring.BatchResponse, error) {
	return s.engine.ScoreBatch(request)
}

func (s *Phase8CCandidateScorer) PolicyReference() candidatescoring.PolicyReference {
	return s.engine.PolicyReference()
}
