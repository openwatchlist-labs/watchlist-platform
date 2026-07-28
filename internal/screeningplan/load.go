package screeningplan

import (
	"encoding/json"
	"fmt"
	"io"
)

func Load(reader io.Reader) (Plan, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, fmt.Errorf("decode screening plan: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Plan{}, fmt.Errorf("decode screening plan: multiple JSON values")
		}
		return Plan{}, fmt.Errorf("decode screening plan trailing content: %w", err)
	}
	return plan, nil
}
