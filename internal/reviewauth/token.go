package reviewauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type TokenService struct {
	Registry Registry
	Key      []byte
	MaxTTL   time.Duration
}

func LoadSigningKey(path string) ([]byte, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	v := strings.TrimSpace(string(b))
	k := []byte(v)
	if x, e := hex.DecodeString(v); e == nil && len(x) > 0 {
		k = x
	}
	if len(k) < 32 {
		return nil, errors.New("signing key must contain at least 32 bytes")
	}
	return k, nil
}
func NewTokenService(r Registry, k []byte, max time.Duration) (*TokenService, error) {
	if e := VerifyRegistry(r); e != nil {
		return nil, e
	}
	r.buildIndex()
	if len(k) < 32 {
		return nil, errors.New("signing key must contain at least 32 bytes")
	}
	if max <= 0 {
		max = 8 * time.Hour
	}
	return &TokenService{r, k, max}, nil
}
func (s *TokenService) Issue(uid, tenant string, ttl time.Duration, now time.Time) (string, Claims, error) {
	var c Claims
	u, ok := s.Registry.User(uid)
	if !ok {
		return "", c, errors.New("unknown user")
	}
	if !u.Active {
		return "", c, errors.New("user is inactive")
	}
	if tenant == "" {
		return "", c, errors.New("tenant is required")
	}
	roles, e := s.Registry.RolesFor(u, tenant)
	if e != nil {
		return "", c, e
	}
	if ttl <= 0 || ttl > s.MaxTTL {
		return "", c, fmt.Errorf("token ttl must be positive and no greater than %s", s.MaxTTL)
	}
	n := make([]byte, 16)
	if _, e = rand.Read(n); e != nil {
		return "", c, e
	}
	iat := now.UTC().Truncate(time.Second)
	seed := uid + ":" + tenant + ":" + iat.Format(time.RFC3339Nano) + ":" + base64.RawURLEncoding.EncodeToString(n)
	c = Claims{ClaimsSchemaV1, "tok_" + HashString(seed)[:24], u.UserID, u.DisplayName, tenant, roles, iat.Format(time.RFC3339Nano), iat.Add(ttl).Format(time.RFC3339Nano), s.Registry.RegistrySHA256, u.SessionEpoch}
	p, e := CanonicalJSON(c)
	if e != nil {
		return "", c, e
	}
	enc := base64.RawURLEncoding.EncodeToString(p)
	signed := "owat1." + enc
	return signed + "." + base64.RawURLEncoding.EncodeToString(s.sign(signed)), c, nil
}
func (s *TokenService) Parse(tok string, now time.Time) (Claims, error) {
	var c Claims
	p := strings.Split(tok, ".")
	if len(p) != 3 || p[0] != "owat1" {
		return c, errors.New("invalid access token format")
	}
	sig, e := base64.RawURLEncoding.DecodeString(p[2])
	if e != nil {
		return c, errors.New("invalid signature encoding")
	}
	signed := p[0] + "." + p[1]
	if !hmac.Equal(sig, s.sign(signed)) {
		return c, errors.New("invalid access token signature")
	}
	raw, e := base64.RawURLEncoding.DecodeString(p[1])
	if e != nil {
		return c, errors.New("invalid payload encoding")
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, errors.New("invalid access token claims")
	}
	if c.SchemaVersion != ClaimsSchemaV1 || c.RegistrySHA256 != s.Registry.RegistrySHA256 {
		return c, errors.New("access token registry lineage is stale")
	}
	iat, e := time.Parse(time.RFC3339Nano, c.IssuedAt)
	if e != nil {
		return c, errors.New("invalid issued_at")
	}
	exp, e := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if e != nil {
		return c, errors.New("invalid expires_at")
	}
	n := now.UTC()
	if n.Before(iat.Add(-30 * time.Second)) {
		return c, errors.New("access token is not yet valid")
	}
	if !n.Before(exp) {
		return c, errors.New("access token is expired")
	}
	if exp.Sub(iat) > s.MaxTTL {
		return c, errors.New("access token ttl exceeds policy")
	}
	u, ok := s.Registry.User(c.Subject)
	if !ok || !u.Active {
		return c, errors.New("access token subject is inactive or unknown")
	}
	if u.SessionEpoch != c.SessionEpoch {
		return c, errors.New("access token session epoch is revoked")
	}
	roles, e := s.Registry.RolesFor(u, c.TenantID)
	if e != nil {
		return c, e
	}
	sort.Strings(roles)
	a := append([]string(nil), c.Roles...)
	sort.Strings(a)
	if strings.Join(roles, "\x00") != strings.Join(a, "\x00") {
		return c, errors.New("access token role binding is stale")
	}
	return c, nil
}
func (s *TokenService) sign(v string) []byte {
	m := hmac.New(sha256.New, s.Key)
	_, _ = m.Write([]byte(v))
	return m.Sum(nil)
}
