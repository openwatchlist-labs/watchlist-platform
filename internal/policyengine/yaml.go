package policyengine

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// parseYAMLMap implements the deliberately small, auditable YAML subset used by
// policy artifacts: indentation-based mappings and scalar values. Sequences,
// anchors, aliases, tags, and multiline scalars are rejected.
func parseYAMLMap(data []byte) (map[string]any, error) {
	root := map[string]any{}
	type frame struct {
		indent int
		value  map[string]any
	}
	stack := []frame{{indent: -2, value: root}}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		raw := strings.TrimRight(scanner.Text(), " \t\r")
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		if strings.Contains(raw, "\t") {
			return nil, fmt.Errorf("line %d: tabs are not allowed", lineNumber)
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent%2 != 0 {
			return nil, fmt.Errorf("line %d: indentation must use two-space steps", lineNumber)
		}
		text := strings.TrimSpace(raw)
		if strings.HasPrefix(text, "-") || strings.Contains(text, "&") || strings.Contains(text, "*") {
			return nil, fmt.Errorf("line %d: sequences, anchors, and aliases are not supported", lineNumber)
		}
		colon := strings.Index(text, ":")
		if colon <= 0 {
			return nil, fmt.Errorf("line %d: expected key: value mapping", lineNumber)
		}
		key := strings.TrimSpace(text[:colon])
		if key == "" || strings.ContainsAny(key, "{}[]") {
			return nil, fmt.Errorf("line %d: invalid key", lineNumber)
		}
		for len(stack) > 1 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		parent := stack[len(stack)-1]
		if indent != parent.indent+2 {
			return nil, fmt.Errorf("line %d: indentation jumps from %d to %d", lineNumber, parent.indent, indent)
		}
		if _, exists := parent.value[key]; exists {
			return nil, fmt.Errorf("line %d: duplicate key %q", lineNumber, key)
		}
		rest := strings.TrimSpace(text[colon+1:])
		if rest == "" {
			child := map[string]any{}
			parent.value[key] = child
			stack = append(stack, frame{indent: indent, value: child})
			continue
		}
		value, err := parseYAMLScalar(rest)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		parent.value[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return root, nil
}

func parseYAMLScalar(value string) (any, error) {
	if strings.Contains(value, " #") {
		value = strings.TrimSpace(strings.SplitN(value, " #", 2)[0])
	}
	if value == "" {
		return nil, fmt.Errorf("empty scalar")
	}
	if strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">") || strings.HasPrefix(value, "!") {
		return nil, fmt.Errorf("multiline scalars and tags are not supported")
	}
	if strings.HasPrefix(value, "\"") {
		parsed, err := strconv.Unquote(value)
		if err != nil {
			return nil, fmt.Errorf("invalid quoted string: %v", err)
		}
		return parsed, nil
	}
	if strings.HasPrefix(value, "'") {
		if len(value) < 2 || !strings.HasSuffix(value, "'") {
			return nil, fmt.Errorf("unterminated single-quoted string")
		}
		return strings.ReplaceAll(value[1:len(value)-1], "''", "'"), nil
	}
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null", "~":
		return nil, nil
	}
	if integer, err := strconv.Atoi(value); err == nil {
		return integer, nil
	}
	if strings.ContainsAny(value, "{}[]") {
		return nil, fmt.Errorf("flow collections are not supported")
	}
	return value, nil
}
