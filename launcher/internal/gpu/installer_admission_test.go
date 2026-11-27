package gpu

import (
	"strings"
	"testing"
)

func TestInstallerHostForRegion(t *testing.T) {
	tests := []struct {
		name     string
		region   string
		wantHost string
		wantErr  bool
	}{
		{name: "us region", region: "us-west1", wantHost: "us.gcr.io"},
		{name: "us multi-zone region", region: "us-east5", wantHost: "us.gcr.io"},
		{name: "europe region", region: "europe-west1", wantHost: "eu.gcr.io"},
		{name: "asia region", region: "asia-east1", wantHost: "asia.gcr.io"},
		{name: "empty region fails closed", region: "", wantErr: true},
		{name: "region without approved source fails closed", region: "australia-southeast1", wantErr: true},
		{name: "garbage region fails closed", region: "moon-1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, err := InstallerHostForRegion(tt.region)
			if (err != nil) != tt.wantErr {
				t.Fatalf("InstallerHostForRegion(%q) error = %v, wantErr %v", tt.region, err, tt.wantErr)
			}
			if err == nil && host != tt.wantHost {
				t.Errorf("InstallerHostForRegion(%q) = %q, want %q", tt.region, host, tt.wantHost)
			}
		})
	}
}

func TestInstallerImageRefForRegion(t *testing.T) {
	tests := []struct {
		region  string
		wantRef string
		wantErr bool
	}{
		{region: "us-west1", wantRef: "us.gcr.io/" + InstallerRepo + ":" + InstallerTag},
		{region: "europe-west4", wantRef: "eu.gcr.io/" + InstallerRepo + ":" + InstallerTag},
		{region: "asia-northeast1", wantRef: "asia.gcr.io/" + InstallerRepo + ":" + InstallerTag},
		{region: "", wantErr: true},
	}
	for _, tt := range tests {
		ref, err := installerImageRefForRegion(tt.region)
		if (err != nil) != tt.wantErr {
			t.Fatalf("installerImageRefForRegion(%q) error = %v, wantErr %v", tt.region, err, tt.wantErr)
		}
		if err == nil && ref != tt.wantRef {
			t.Errorf("installerImageRefForRegion(%q) = %q, want %q", tt.region, ref, tt.wantRef)
		}
	}
}

func TestAdmitInstallerComponents(t *testing.T) {
	const otherDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	tests := []struct {
		name         string
		imageRef     string
		pinnedDigest string
		region       string
		wantRef      string
		wantErr      bool
		errSubstr    string
	}{
		{
			name:         "source, trust root, and region agree",
			imageRef:     "us.gcr.io/" + InstallerRepo + ":" + InstallerTag,
			pinnedDigest: InstallerDigest,
			region:       "us-west1",
			wantRef:      "us.gcr.io/" + InstallerRepo + ":" + InstallerTag + "@" + InstallerDigest,
		},
		{
			name:         "europe node admits european source",
			imageRef:     "eu.gcr.io/" + InstallerRepo + ":" + InstallerTag,
			pinnedDigest: InstallerDigest,
			region:       "europe-west1",
			wantRef:      "eu.gcr.io/" + InstallerRepo + ":" + InstallerTag + "@" + InstallerDigest,
		},
		{
			name:         "component pulled from the wrong region is rejected",
			imageRef:     "us.gcr.io/" + InstallerRepo + ":" + InstallerTag,
			pinnedDigest: InstallerDigest,
			region:       "europe-west1",
			wantErr:      true,
			errSubstr:    "does not match the approved host",
		},
		{
			name:         "non-Google source is rejected",
			imageRef:     "evil.example.com/" + InstallerRepo + ":" + InstallerTag,
			pinnedDigest: InstallerDigest,
			region:       "us-west1",
			wantErr:      true,
			errSubstr:    "does not match the approved host",
		},
		{
			name:         "unapproved repository is rejected",
			imageRef:     "us.gcr.io/cos-cloud/not-the-installer:" + InstallerTag,
			pinnedDigest: InstallerDigest,
			region:       "us-west1",
			wantErr:      true,
			errSubstr:    "is not the approved",
		},
		{
			name:         "unapproved tag is rejected",
			imageRef:     "us.gcr.io/" + InstallerRepo + ":v0.0.0",
			pinnedDigest: InstallerDigest,
			region:       "us-west1",
			wantErr:      true,
			errSubstr:    "is not the approved",
		},
		{
			name:         "stale trust root is rejected",
			imageRef:     "us.gcr.io/" + InstallerRepo + ":" + InstallerTag,
			pinnedDigest: otherDigest,
			region:       "us-west1",
			wantErr:      true,
			errSubstr:    "does not match the approved digest",
		},
		{
			name:         "malformed trust root is rejected",
			imageRef:     "us.gcr.io/" + InstallerRepo + ":" + InstallerTag,
			pinnedDigest: "sha256:not-hex",
			region:       "us-west1",
			wantErr:      true,
			errSubstr:    "not a well-formed sha256 digest",
		},
		{
			name:         "empty trust root is rejected",
			imageRef:     "us.gcr.io/" + InstallerRepo + ":" + InstallerTag,
			pinnedDigest: "",
			region:       "us-west1",
			wantErr:      true,
			errSubstr:    "not a well-formed sha256 digest",
		},
		{
			name:         "empty target region is rejected",
			imageRef:     "us.gcr.io/" + InstallerRepo + ":" + InstallerTag,
			pinnedDigest: InstallerDigest,
			region:       "",
			wantErr:      true,
			errSubstr:    "no approved GPU driver installer source",
		},
		{
			name:         "target region without approved source is rejected",
			imageRef:     "us.gcr.io/" + InstallerRepo + ":" + InstallerTag,
			pinnedDigest: InstallerDigest,
			region:       "southamerica-east1",
			wantErr:      true,
			errSubstr:    "no approved GPU driver installer source",
		},
		{
			name:         "source without registry host is rejected",
			imageRef:     InstallerRepo + ":" + InstallerTag,
			pinnedDigest: InstallerDigest,
			region:       "us-west1",
			wantErr:      true,
			errSubstr:    "no registry host",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := admitInstallerComponents(tt.imageRef, tt.pinnedDigest, tt.region)
			if (err != nil) != tt.wantErr {
				t.Fatalf("admitInstallerComponents(%q, %q, %q) error = %v, wantErr %v", tt.imageRef, tt.pinnedDigest, tt.region, err, tt.wantErr)
			}
			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("admitInstallerComponents(%q, %q, %q) error = %v, want substring %q", tt.imageRef, tt.pinnedDigest, tt.region, err, tt.errSubstr)
				}
				return
			}
			if ref != tt.wantRef {
				t.Errorf("admitInstallerComponents(%q, %q, %q) = %q, want %q", tt.imageRef, tt.pinnedDigest, tt.region, ref, tt.wantRef)
			}
		})
	}
}

func TestAdmitInstallerComponentsPullsByDigest(t *testing.T) {
	for _, region := range []string{"us-west1", "europe-west1", "asia-east1"} {
		imageRef, err := installerImageRefForRegion(region)
		if err != nil {
			t.Fatalf("installerImageRefForRegion(%q) failed: %v", region, err)
		}
		ref, err := admitInstallerComponents(imageRef, InstallerDigest, region)
		if err != nil {
			t.Fatalf("admitInstallerComponents(%q, InstallerDigest, %q) failed: %v", imageRef, region, err)
		}
		if !strings.HasSuffix(ref, "@"+InstallerDigest) {
			t.Errorf("admitted reference %q for region %q is not pinned to InstallerDigest %q", ref, region, InstallerDigest)
		}
	}
}
