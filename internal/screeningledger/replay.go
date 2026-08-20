package screeningledger

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

func (s *Store) Replay(ctx context.Context, eventID, backendURL string, client *http.Client) (ReplayReport, error) {
	event, err := s.GetEvent(eventID)
	if err != nil {
		return ReplayReport{}, err
	}
	request, err := s.DecryptSnapshot(event.RequestSnapshotSHA256)
	if err != nil {
		return ReplayReport{SchemaVersion: "openwatchlist.screening-replay-report.v1", EventID: eventID, Classification: "unreproducible", OriginalResponseSHA256: event.ResponseSHA256, Error: err.Error()}, nil
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(backendURL, "/")+event.Route, bytes.NewReader(request))
	if err != nil {
		return ReplayReport{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return ReplayReport{SchemaVersion: "openwatchlist.screening-replay-report.v1", EventID: eventID, Classification: "unreproducible", OriginalResponseSHA256: event.ResponseSHA256, Error: err.Error()}, nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ReplayReport{}, err
	}
	report := ReplayReport{SchemaVersion: "openwatchlist.screening-replay-report.v1", EventID: eventID, OriginalResponseSHA256: event.ResponseSHA256, ReplayResponseSHA256: digestHex(body), HTTPStatus: resp.StatusCode}
	if report.ReplayResponseSHA256 == event.ResponseSHA256 {
		report.Classification = "exact"
	} else {
		report.Classification = "explainable_drift"
		original, _ := s.DecryptSnapshot(event.ResponseSnapshotSHA256)
		report.CandidateDelta = compareCandidates(original, body)
	}
	_, _ = s.AppendAudit("replay", "", "", eventID, report)
	return report, nil
}
func compareCandidates(left, right []byte) json.RawMessage {
	extract := func(raw []byte) []string {
		var doc map[string]any
		if json.Unmarshal(raw, &doc) != nil {
			return nil
		}
		values := []string{}
		if candidates, ok := doc["candidates"].([]any); ok {
			for _, v := range candidates {
				if c, ok := v.(map[string]any); ok {
					values = append(values, fmt.Sprint(c["candidate_id"])+":"+fmt.Sprint(c["score"]))
				}
			}
		}
		sort.Strings(values)
		return values
	}
	raw, _ := json.Marshal(map[string]any{"original": extract(left), "replay": extract(right)})
	return raw
}
func (s *Store) ExportBundle(eventID, outPath, mode string, policy RetentionPolicy) (BundleManifest, error) {
	if mode != "redacted" && mode != "internal" {
		return BundleManifest{}, errors.New("bundle mode must be redacted or internal")
	}
	event, err := s.GetEvent(eventID)
	if err != nil {
		return BundleManifest{}, err
	}
	request, err := s.DecryptSnapshot(event.RequestSnapshotSHA256)
	if err != nil {
		return BundleManifest{}, err
	}
	response, err := s.DecryptSnapshot(event.ResponseSnapshotSHA256)
	if err != nil {
		return BundleManifest{}, err
	}
	if mode == "redacted" {
		request, err = RedactJSON(request, policy, s.keys.redact)
		if err != nil {
			return BundleManifest{}, err
		}
		response, err = RedactJSON(response, policy, s.keys.redact)
		if err != nil {
			return BundleManifest{}, err
		}
	}
	files := map[string][]byte{}
	eventRaw, err := json.Marshal(event)
	if err != nil {
		return BundleManifest{}, err
	}
	files["event.json"] = eventRaw
	files["request.json"] = request
	files["response.json"] = response
	if raw, err := os.ReadFile(s.directory + "/audit-head.json"); err == nil {
		files["audit-head.json"] = raw
	}
	manifest := BundleManifest{SchemaVersion: BundleSchemaV1, EventID: eventID, Mode: mode, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Files: map[string]string{}}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	concat := bytes.Buffer{}
	for _, name := range names {
		manifest.Files[name] = digestHex(files[name])
		concat.WriteString(name)
		concat.WriteByte('\n')
		concat.Write(files[name])
		concat.WriteByte('\n')
	}
	manifest.BundleSHA256 = digestHex(concat.Bytes())
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return BundleManifest{}, err
	}
	files["manifest.json"] = manifestRaw
	f, err := os.Create(outPath)
	if err != nil {
		return BundleManifest{}, err
	}
	zw := zip.NewWriter(f)
	for _, name := range append(names, "manifest.json") {
		w, err := zw.Create(name)
		if err != nil {
			_ = zw.Close()
			_ = f.Close()
			return BundleManifest{}, err
		}
		if _, err = w.Write(files[name]); err != nil {
			_ = zw.Close()
			_ = f.Close()
			return BundleManifest{}, err
		}
	}
	if err = zw.Close(); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return BundleManifest{}, err
	}
	_, _ = s.AppendAudit("export_bundle", "", "", eventID, map[string]any{"mode": mode, "bundle_sha256": manifest.BundleSHA256})
	return manifest, nil
}

// PurgeExpired is ADR-0007 Addendum 2 D27/D28's local-narrows/server-floors
// purge path. It gains a required PurgeRecorder and refuses without one
// (D28: "a purge whose independence cannot be recorded must not happen,
// rather than happening and silently rendering the ledger permanently
// unverifiable" -- the failure mode replay.go used to reach with no
// independent record at all, before this fix, when a snapshot was purged
// locally and never synced).
//
// The local side determines eligibility exactly as before (legal holds,
// which the server does not and should not learn about a filesystem
// directory -- D28's "narrows"), then hands recorder that eligible set.
// recorder re-validates every one of them against its own expiry floor
// and returns exactly which it actually recorded (D28's "floors") -- only
// those may be marked purged in the local envelope, regardless of what
// this side believed was eligible.
func (s *Store) PurgeExpired(ctx context.Context, now time.Time, operator, reason string, recorder PurgeRecorder) (int, error) {
	if recorder == nil {
		return 0, errors.New("purge requires a PurgeRecorder (ADR-0007 Addendum 2 D28): a purge whose independence cannot be recorded must not happen")
	}
	events, err := s.ListEvents()
	if err != nil {
		return 0, err
	}
	references := map[string][]Event{}
	for _, event := range events {
		references[event.RequestSnapshotSHA256] = append(references[event.RequestSnapshotSHA256], event)
		references[event.ResponseSnapshotSHA256] = append(references[event.ResponseSnapshotSHA256], event)
	}
	eligible := []string{}
	for sha, refs := range references {
		ok := true
		for _, event := range refs {
			if _, err := os.Stat(s.directory + "/holds/" + event.EventID); err == nil {
				ok = false
				break
			}
			expires, err := time.Parse(time.RFC3339Nano, event.ExpiresAt)
			if err != nil || now.Before(expires) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		env, err := s.LoadSnapshot(sha)
		if err != nil {
			return 0, err
		}
		if env.PurgedAt != "" {
			continue
		}
		eligible = append(eligible, sha)
	}

	recorded, err := recorder.RecordPurge(ctx, eligible, now, operator, reason)
	if err != nil {
		return 0, err
	}
	recordedSet := make(map[string]bool, len(recorded))
	for _, sha := range recorded {
		recordedSet[sha] = true
	}

	purgedSHA256 := []string{}
	for _, sha := range eligible {
		if !recordedSet[sha] {
			// The server's own floor did not confirm this snapshot as
			// expired (e.g. clock skew against the local now, or it was
			// already recorded independently) -- do not mark it purged
			// locally on the strength of the local side's belief alone.
			continue
		}
		env, err := s.LoadSnapshot(sha)
		if err != nil {
			return len(purgedSHA256), err
		}
		env.CiphertextBase64 = ""
		env.NonceBase64 = ""
		env.PurgedAt = now.UTC().Format(time.RFC3339Nano)
		env.PurgeReason = reason
		raw, _ := json.Marshal(env)
		if err := atomicWrite(s.snapshotPath(sha), raw, 0o600); err != nil {
			return len(purgedSHA256), err
		}
		purgedSHA256 = append(purgedSHA256, sha)
	}
	// ADR-0007 Addendum 3 D32: the audit entry attests the sorted,
	// deduplicated set of snapshot sha256 values purged, not merely a
	// count -- VerifyAnchored's adjudicatePurgeClaims reads this back to
	// decide whether a specific purged snapshot is legitimate. eligible
	// is already deduplicated (built from a map in the caller above), so
	// sorting alone gives a deterministic, dedup set.
	sort.Strings(purgedSHA256)
	_, err = s.AppendAudit("purge_expired", operator, reason, "", purgeExpiredAuditDetails{SnapshotSHA256: purgedSHA256})
	return len(purgedSHA256), err
}
