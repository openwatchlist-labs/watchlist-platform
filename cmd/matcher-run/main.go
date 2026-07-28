package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherbaseline"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matchercontext"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/providerentity"
)

func main() {
	catalogPath := flag.String("catalog", "test/fixtures/providers/synthetic/synthetic-catalog-v1.json", "provider catalog JSON or compiled runtime package")
	providerKind := flag.String("provider", "fixture", "provider adapter: fixture, ofac-direct, ofac-runtime, ofac-baseline, ofac-context, provider-entity, or hybrid-overlay")
	overlayCatalogPath := flag.String("overlay-catalog", "", "OFAC direct-list overlay catalog for hybrid-overlay")
	matcherProfilesPath := flag.String("matcher-profiles", "configs/matcher-profiles/ofac-name-baseline-r1.json", "name matcher threshold profile set for ofac-baseline or ofac-context")
	contextProfilesPath := flag.String("context-profiles", "configs/matcher-profiles/ofac-context-baseline-r1.json", "context matcher profile set for ofac-context")
	jurisdictionPolicyPath := flag.String("jurisdiction-policy", "", "jurisdiction policy set for ofac-context (required)")
	inputKind := flag.String("input", "requests", "input JSON contract: requests or replay")
	outputKind := flag.String("output", "results", "output JSON contract: results or replay")
	generationPath := flag.String("generation-stamp", "", "optional generation stamp or active-pointer JSON")
	compact := flag.Bool("compact", false, "emit compact JSON")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: matcher-run [flags] <matcher request or replay JSON>")
		flag.PrintDefaults()
		os.Exit(2)
	}
	if (*inputKind == "requests" && *outputKind != "results") || (*inputKind == "replay" && *outputKind != "replay") {
		fmt.Fprintln(os.Stderr, "supported input/output pairs are requests/results and replay/replay")
		os.Exit(2)
	}
	if *inputKind != "requests" && *inputKind != "replay" {
		fmt.Fprintf(os.Stderr, "unsupported --input %q; expected requests or replay\n", *inputKind)
		os.Exit(2)
	}

	var provider matcherprovider.Provider
	var loadedRuntime *ofacruntime.LoadedPackage
	var err error
	switch *providerKind {
	case "fixture":
		catalog, openErr := os.Open(*catalogPath)
		check(openErr, "open provider catalog")
		provider, err = matcherprovider.LoadFixtureProvider(catalog)
		_ = catalog.Close()
	case "ofac-direct":
		catalog, openErr := os.Open(*catalogPath)
		check(openErr, "open provider catalog")
		var direct ofaccatalog.Catalog
		direct, err = ofaccatalog.Load(catalog)
		_ = catalog.Close()
		if err == nil {
			provider, err = ofaccatalog.NewProvider(direct)
		}
	case "provider-entity":
		catalog, openErr := os.Open(*catalogPath)
		check(openErr, "open provider-entity catalog")
		var entityCatalog providerentity.Catalog
		entityCatalog, err = providerentity.LoadCatalog(catalog)
		_ = catalog.Close()
		if err == nil {
			provider, err = providerentity.NewProvider(entityCatalog)
		}
	case "hybrid-overlay":
		if *overlayCatalogPath == "" {
			err = fmt.Errorf("--overlay-catalog is required for hybrid-overlay")
			break
		}
		baseFile, openErr := os.Open(*catalogPath)
		check(openErr, "open provider-entity catalog")
		baseCatalog, loadErr := providerentity.LoadCatalog(baseFile)
		_ = baseFile.Close()
		if loadErr != nil {
			err = loadErr
			break
		}
		overlayFile, openErr := os.Open(*overlayCatalogPath)
		check(openErr, "open direct overlay catalog")
		overlayCatalog, loadErr := ofaccatalog.Load(overlayFile)
		_ = overlayFile.Close()
		if loadErr != nil {
			err = loadErr
			break
		}
		provider, _, err = providerentity.NewHybridProvider(baseCatalog, overlayCatalog)
	case "ofac-runtime", "ofac-baseline", "ofac-context":
		data, readErr := os.ReadFile(*catalogPath)
		check(readErr, "read compiled runtime package")
		loadedRuntime, err = ofacruntime.Load(data)
		if err == nil && *providerKind == "ofac-runtime" {
			provider = loadedRuntime.Provider
		}
		if err == nil && (*providerKind == "ofac-baseline" || *providerKind == "ofac-context") {
			profilesFile, openErr := os.Open(*matcherProfilesPath)
			check(openErr, "open name matcher threshold profiles")
			profiles, loadErr := matcherbaseline.LoadProfileSet(profilesFile)
			_ = profilesFile.Close()
			if loadErr != nil {
				err = loadErr
			} else if *providerKind == "ofac-baseline" {
				provider, err = matcherbaseline.NewProvider(loadedRuntime.Payload, profiles)
			} else {
				if *jurisdictionPolicyPath == "" {
					err = fmt.Errorf("--jurisdiction-policy is required for ofac-context")
				} else {
					contextFile, openErr := os.Open(*contextProfilesPath)
					check(openErr, "open context matcher profiles")
					contextProfiles, contextErr := matchercontext.LoadProfileSet(contextFile)
					_ = contextFile.Close()
					if contextErr != nil {
						err = contextErr
					} else {
						policyFile, openErr := os.Open(*jurisdictionPolicyPath)
						check(openErr, "open jurisdiction policy")
						policy, policyErr := matchercontext.LoadPolicySet(policyFile)
						_ = policyFile.Close()
						if policyErr != nil {
							err = policyErr
						} else {
							provider, err = matchercontext.NewProvider(loadedRuntime.Payload, profiles, contextProfiles, policy)
						}
					}
				}
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "unsupported --provider %q; expected fixture, ofac-direct, ofac-runtime, ofac-baseline, ofac-context, provider-entity, or hybrid-overlay\n", *providerKind)
		os.Exit(2)
	}
	check(err, "load provider catalog")
	runner, err := matcherprovider.NewRunner(provider)
	check(err, "create matcher provider runner")

	var generation *catalogruntime.GenerationStamp
	if *generationPath != "" {
		stamp := loadGenerationStamp(*generationPath)
		if loadedRuntime != nil && (stamp.PackageID != loadedRuntime.Info.PackageID || stamp.PackageChecksum != loadedRuntime.Info.PackageChecksum || stamp.SourceManifestID != loadedRuntime.Info.Manifest.SourceManifestID) {
			check(fmt.Errorf("generation stamp package lineage differs from compiled runtime package"), "validate generation stamp")
		}
		generation = &stamp
	}

	input, err := os.Open(flag.Arg(0))
	check(err, "open matcher input")
	defer input.Close()

	var output any
	switch *inputKind {
	case "requests":
		var batch matcherrequest.RequestBatch
		check(decodeStrict(input, &batch), "decode matcher request batch")
		if generation == nil {
			output, err = runner.Execute(context.Background(), batch)
		} else {
			output, err = runner.ExecuteStamped(context.Background(), batch, *generation)
		}
		check(err, "execute matcher provider")
	case "replay":
		var replay matcherrequest.ReplayEnvelope
		check(decodeStrict(input, &replay), "decode matcher replay envelope")
		if generation == nil {
			output, err = runner.Replay(context.Background(), replay)
		} else {
			output, err = runner.ReplayStamped(context.Background(), replay, *generation)
		}
		check(err, "execute matcher provider replay")
	}

	encoder := json.NewEncoder(os.Stdout)
	if !*compact {
		encoder.SetIndent("", "  ")
	}
	encoder.SetEscapeHTML(false)
	check(encoder.Encode(output), "encode JSON output")
}

func loadGenerationStamp(path string) catalogruntime.GenerationStamp {
	data, err := os.ReadFile(path)
	check(err, "read generation stamp")
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	check(json.Unmarshal(data, &header), "decode generation stamp header")
	var stamp catalogruntime.GenerationStamp
	switch header.SchemaVersion {
	case catalogruntime.GenerationStampSchemaVersion:
		check(decodeStrict(bytes.NewReader(data), &stamp), "decode generation stamp")
	case catalogruntime.ActivePointerSchemaVersion:
		var pointer catalogruntime.ActivePointer
		check(decodeStrict(bytes.NewReader(data), &pointer), "decode active pointer")
		stamp = pointer.Generation
	default:
		check(fmt.Errorf("unsupported schema_version %q", header.SchemaVersion), "decode generation stamp")
	}
	check(catalogruntime.ValidateGenerationStamp(stamp), "validate generation stamp")
	return stamp
}

func decodeStrict(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func check(err error, operation string) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	os.Exit(1)
}
