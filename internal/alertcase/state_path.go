package alertcase

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	alertIDPattern = regexp.MustCompile(`\Aalert_[0-9a-f]{32}\z`)
	caseIDPattern  = regexp.MustCompile(`\Acase_[0-9a-f]{32}\z`)
	hex64Pattern   = regexp.MustCompile(`\A[0-9a-f]{64}\z`)
)

func validateAlertID(id string) error {
	if !alertIDPattern.MatchString(id) {
		return fmt.Errorf("invalid alert_id %q", id)
	}
	return nil
}

func validateCaseID(id string) error {
	if !caseIDPattern.MatchString(id) {
		return fmt.Errorf("invalid case_id %q", id)
	}
	return nil
}

func validateHex64(label, value string) error {
	if !hex64Pattern.MatchString(value) {
		return fmt.Errorf("invalid %s %q", label, value)
	}
	return nil
}

func confinedStatePath(root string, parts ...string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("state root is required")
	}
	if len(parts) == 0 {
		return "", errors.New("state path components are required")
	}
	for _, part := range parts {
		if part == "" || strings.ContainsRune(part, '\x00') || strings.Contains(part, `\`) {
			return "", fmt.Errorf("unsafe state path component %q", part)
		}
	}
	rel := filepath.Join(parts...)
	if rel == "." || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("unsafe state relative path %q", rel)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolvedRoot := rootAbs
	if evaluated, evalErr := filepath.EvalSymlinks(rootAbs); evalErr == nil {
		resolvedRoot = evaluated
	}
	candidate := filepath.Join(resolvedRoot, rel)
	relCheck, err := filepath.Rel(resolvedRoot, candidate)
	if err != nil || relCheck == "." || !filepath.IsLocal(relCheck) {
		return "", fmt.Errorf("state path escapes root: %q", rel)
	}
	current := resolvedRoot
	for _, component := range strings.Split(relCheck, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("state path contains symlink component %q", component)
		}
	}
	return candidate, nil
}

func (s *Store) alertPath(id string) (string, error) {
	if err := validateAlertID(id); err != nil {
		return "", err
	}
	return confinedStatePath(s.Dir, "alerts", id+".json")
}

func (s *Store) casePath(id string, parts ...string) (string, error) {
	if err := validateCaseID(id); err != nil {
		return "", err
	}
	all := append([]string{"cases", id}, parts...)
	return confinedStatePath(s.Dir, all...)
}
