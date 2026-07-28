package ofacruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func stablePackageID(manifest PackageManifest) string {
	sum := sha256.Sum256([]byte(strings.Join(packageSeed(manifest), "\x1f")))
	return "runtime_package_" + hex.EncodeToString(sum[:12])
}
