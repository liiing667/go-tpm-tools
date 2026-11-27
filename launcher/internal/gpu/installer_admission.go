package gpu

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// regionalInstallerHosts maps a GCE region prefix to the Google Container
// Registry host that serves the approved GPU driver installer components for
// nodes in that region. Regions without an approved regional source have no
// entry on purpose: admission fails closed instead of falling back to a
// source the node has no regional binding to.
var regionalInstallerHosts = []struct {
	regionPrefix string
	host         string
}{
	{"us-", "us.gcr.io"},
	{"europe-", "eu.gcr.io"},
	{"asia-", "asia.gcr.io"},
}

// InstallerHostForRegion returns the registry host that serves the approved
// GPU driver installer components for the given GCE region (for example
// "us-west1" -> "us.gcr.io"). It fails closed: a node whose target region has
// no approved installer source gets an error, never a fallback source.
func InstallerHostForRegion(region string) (string, error) {
	for _, mapping := range regionalInstallerHosts {
		if strings.HasPrefix(region, mapping.regionPrefix) {
			return mapping.host, nil
		}
	}
	return "", fmt.Errorf("no approved GPU driver installer source for region %q", region)
}

// installerImageRefForRegion returns the approved installer image reference
// (host/repository:tag, without the digest) for the node's target region.
func installerImageRefForRegion(region string) (string, error) {
	host, err := InstallerHostForRegion(region)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s:%s", host, InstallerRepo, InstallerTag), nil
}

// admitInstallerComponents forms the single admission conclusion for the GPU
// driver installer components. Three inputs must agree, or nothing is pulled
// and nothing is installed into the trusted boot chain:
//
//   - component source: imageRef must live on the approved regional registry
//     host for targetRegion and must name the approved repository and tag;
//   - pinned trust root: pinnedDigest must be a well-formed SHA-256 digest
//     and must equal InstallerDigest;
//   - target region: targetRegion must have an approved installer source.
//
// It returns the digest-pinned pull reference (host/repository:tag@digest)
// on success, so containerd rejects any other manifest before downloading
// layers.
func admitInstallerComponents(imageRef, pinnedDigest, targetRegion string) (string, error) {
	wantHost, err := InstallerHostForRegion(targetRegion)
	if err != nil {
		return "", err
	}

	host, repo, tag, err := parseImageRef(imageRef)
	if err != nil {
		return "", err
	}
	if host != wantHost {
		return "", fmt.Errorf("installer source host %q does not match the approved host %q for target region %q", host, wantHost, targetRegion)
	}
	if repo != InstallerRepo || tag != InstallerTag {
		return "", fmt.Errorf("installer source %q is not the approved %s:%s", imageRef, InstallerRepo, InstallerTag)
	}
	if !isSHA256Digest(pinnedDigest) {
		return "", fmt.Errorf("pinned installer digest %q is not a well-formed sha256 digest", pinnedDigest)
	}
	if pinnedDigest != InstallerDigest {
		return "", fmt.Errorf("pinned installer digest %q does not match the approved digest %q", pinnedDigest, InstallerDigest)
	}
	return fmt.Sprintf("%s/%s:%s@%s", host, repo, tag, pinnedDigest), nil
}

// parseImageRef splits a host/repository:tag image reference into its parts.
func parseImageRef(imageRef string) (host, repo, tag string, err error) {
	slash := strings.Index(imageRef, "/")
	if slash <= 0 {
		return "", "", "", fmt.Errorf("installer image reference %q has no registry host", imageRef)
	}
	host, rest := imageRef[:slash], imageRef[slash+1:]
	if !strings.Contains(host, ".") {
		return "", "", "", fmt.Errorf("installer image reference %q has no registry host", imageRef)
	}
	repo, tag, ok := strings.Cut(rest, ":")
	if !ok || repo == "" || tag == "" {
		return "", "", "", fmt.Errorf("installer image reference %q must be in host/repository:tag form", imageRef)
	}
	return host, repo, tag, nil
}

// isSHA256Digest reports whether s is a "sha256:" prefixed 64-hex-digit digest.
func isSHA256Digest(s string) bool {
	hexPart, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(hexPart) != 64 {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil
}
