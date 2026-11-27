package cmd

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/compute/metadata"
)

// metadataIdentityReader is the subset of *metadata.Client used to resolve a
// command's GCE identity. It exists so tests can give every command its own
// metadata endpoint without mutating process-wide environment variables.
type metadataIdentityReader interface {
	GetWithContext(context.Context, string) (string, error)
	ZoneWithContext(context.Context) (string, error)
}

var _ metadataIdentityReader = (*metadata.Client)(nil)

func trimmedMetadataValue(ctx context.Context, client metadataIdentityReader, path string) (string, error) {
	value, err := client.GetWithContext(ctx, path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

// metadataProjectID reads the project directly from MDS. It deliberately does
// not use metadata.Client.ProjectIDWithContext: the metadata package backs
// that method with process-global cached state, which can leak one command's
// project into a later command running in the same process.
func metadataProjectID(ctx context.Context, client metadataIdentityReader) (string, error) {
	return trimmedMetadataValue(ctx, client, "project/project-id")
}

// metadataNumericProjectID reads the project number directly from MDS for the
// same reason as metadataProjectID.
func metadataNumericProjectID(ctx context.Context, client metadataIdentityReader) (string, error) {
	return trimmedMetadataValue(ctx, client, "project/numeric-project-id")
}

// metadataInstanceID reads the instance ID directly from MDS.
func metadataInstanceID(ctx context.Context, client metadataIdentityReader) (string, error) {
	return trimmedMetadataValue(ctx, client, "instance/id")
}

// metadataRegion derives the region from the zone using the supplied context.
// metadata.Client.ZoneWithContext is not backed by the package's global value
// cache, unlike ProjectIDWithContext and InstanceIDWithContext.
func metadataRegion(ctx context.Context, client metadataIdentityReader) (string, error) {
	zone, err := client.ZoneWithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve zone from MDS: %w", err)
	}
	lastDash := strings.LastIndex(zone, "-")
	if lastDash == -1 {
		return "", fmt.Errorf("got malformed zone from MDS: %q", zone)
	}
	return zone[:lastDash], nil
}
