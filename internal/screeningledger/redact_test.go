package screeningledger

import "testing"

func TestHmacHexSurfacesMarshalError(t *testing.T) {
	if _, err := hmacHex([]byte("secret"), make(chan int)); err == nil {
		t.Fatal("expected hmacHex to return an error when the value cannot be marshaled")
	}
}

func TestRedactValuePropagatesHashMarshalError(t *testing.T) {
	value := map[string]any{"secret": make(chan int)}
	hash := map[string]struct{}{"secret": {}}
	if _, err := redactValue(value, map[string]struct{}{}, hash, []byte("key")); err == nil {
		t.Fatal("expected redactValue to surface hmacHex's marshal error instead of silently discarding it")
	}
}
