package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"cloud.google.com/go/compute/metadata"
	"github.com/spf13/cobra"
)

type uid43586FakeRWC struct {
	bytes.Buffer
}

func (*uid43586FakeRWC) Close() error { return nil }

func newUID43586TokenRoot(t *testing.T, identity string, captured *tokenOptions) (*cobra.Command, *bytes.Buffer, *string) {
	t.Helper()

	rwc := &uid43586FakeRWC{}
	output := &bytes.Buffer{}
	var openedPath string
	o := &gotpmOptions{
		stdout: output,
		tpmOpener: func(path string) (io.ReadWriteCloser, error) {
			openedPath = path
			return rwc, nil
		},
		runToken: func(_ context.Context, _ io.ReadWriter, opts tokenOptions) ([]byte, error) {
			*captured = opts
			return []byte("token-" + identity), nil
		},
	}
	root := newGotpmCommand(o)
	root.SetOut(output)
	root.SetErr(io.Discard)
	return root, output, &openedPath
}

func TestUID43586TokenCommandsDoNotInheritOptions(t *testing.T) {
	dir := t.TempDir()
	firstOutput := filepath.Join(dir, "first.txt")

	var firstOpts, secondOpts tokenOptions
	firstRoot, _, firstTPMPath := newUID43586TokenRoot(t, "first", &firstOpts)
	firstRoot.SetArgs([]string{
		"token",
		"--tpm-path", "/dev/first-tpm",
		"--audience", "audience-first",
		"--tee-technology", tdx,
		"--output", firstOutput,
	})
	if err := firstRoot.Execute(); err != nil {
		t.Fatalf("first token command failed: %v", err)
	}

	firstToken, err := os.ReadFile(firstOutput)
	if err != nil {
		t.Fatalf("reading first output: %v", err)
	}
	if string(firstToken) != "token-first" {
		t.Fatalf("first token = %q, want %q", firstToken, "token-first")
	}
	if firstOpts.Audience != "audience-first" || firstOpts.TEETechnology != tdx || firstOpts.OutputPath != firstOutput {
		t.Fatalf("first command options = %+v", firstOpts)
	}
	if *firstTPMPath != "/dev/first-tpm" {
		t.Fatalf("first TPM path = %q, want /dev/first-tpm", *firstTPMPath)
	}

	secondOutput := &bytes.Buffer{}
	var openedSecondPath string
	rwc := &uid43586FakeRWC{}
	o := &gotpmOptions{
		stdout: secondOutput,
		tpmOpener: func(path string) (io.ReadWriteCloser, error) {
			openedSecondPath = path
			return rwc, nil
		},
		runToken: func(_ context.Context, _ io.ReadWriter, opts tokenOptions) ([]byte, error) {
			secondOpts = opts
			return []byte("token-second"), nil
		},
	}
	secondRoot := newGotpmCommand(o)
	secondRoot.SetOut(secondOutput)
	secondRoot.SetErr(io.Discard)
	secondRoot.SetArgs([]string{"token", "--audience", "audience-second"})
	if err := secondRoot.Execute(); err != nil {
		t.Fatalf("second token command failed: %v", err)
	}

	if openedSecondPath != "" {
		t.Fatalf("second command inherited tpm path %q", openedSecondPath)
	}
	if secondOpts.TEETechnology != "" {
		t.Fatalf("second command inherited TEE technology %q", secondOpts.TEETechnology)
	}
	if secondOpts.OutputPath != "" {
		t.Fatalf("second command inherited output path %q", secondOpts.OutputPath)
	}
	if got := secondOutput.String(); got != "token-second\n" {
		t.Fatalf("second stdout = %q, want its own token", got)
	}
}

func TestUID43586ConcurrentTokenCommandsWriteOwnResults(t *testing.T) {
	dir := t.TempDir()
	const count = 24

	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("cmd-%02d", i)
			outputPath := filepath.Join(dir, id+".token")
			var opts tokenOptions
			root, _, _ := newUID43586TokenRoot(t, id, &opts)
			root.SetArgs([]string{"token", "--audience", "aud-" + id, "--output", outputPath})
			if err := root.Execute(); err != nil {
				errs <- fmt.Errorf("%s: %w", id, err)
				return
			}
			data, err := os.ReadFile(outputPath)
			if err != nil {
				errs <- fmt.Errorf("%s read: %w", id, err)
				return
			}
			if want := "token-" + id; string(data) != want {
				errs <- fmt.Errorf("%s wrote %q, want %q", id, data, want)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

type uid43586MetadataRoundTrip struct {
	target string
}

func (rt uid43586MetadataRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	target, err := url.Parse(rt.target)
	if err != nil {
		return nil, err
	}
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func newUID43586MetadataClient(t *testing.T, project string) *metadata.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/computeMetadata/v1/project/project-id", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, project)
	})
	mux.HandleFunc("/computeMetadata/v1/project/numeric-project-id", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "12345-"+project)
	})
	mux.HandleFunc("/computeMetadata/v1/instance/id", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "instance-"+project)
	})
	mux.HandleFunc("/computeMetadata/v1/instance/zone", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "projects/123/zones/us-test1-a")
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return metadata.NewClient(&http.Client{Transport: uid43586MetadataRoundTrip{target: server.URL}})
}

func TestUID43586MetadataIdentityBypassesGlobalCache(t *testing.T) {
	ctx := context.Background()
	clients := map[string]*metadata.Client{
		"project-a": newUID43586MetadataClient(t, "project-a"),
		"project-b": newUID43586MetadataClient(t, "project-b"),
	}

	var wg sync.WaitGroup
	for project, client := range clients {
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(project string, client *metadata.Client) {
				defer wg.Done()
				got, err := metadataProjectID(ctx, client)
				if err != nil {
					t.Error(err)
					return
				}
				if got != project {
					t.Errorf("project ID = %q, want %q", got, project)
				}
				number, err := metadataNumericProjectID(ctx, client)
				if err != nil {
					t.Error(err)
					return
				}
				if !strings.HasSuffix(number, project) {
					t.Errorf("project number = %q, want identity for %q", number, project)
				}
				instance, err := metadataInstanceID(ctx, client)
				if err != nil {
					t.Error(err)
					return
				}
				if instance != "instance-"+project {
					t.Errorf("instance ID = %q, want instance-%s", instance, project)
				}
				region, err := metadataRegion(ctx, client)
				if err != nil {
					t.Error(err)
					return
				}
				if region != "us-test1" {
					t.Errorf("region = %q, want us-test1", region)
				}
			}(project, client)
		}
	}
	wg.Wait()
}

func TestUID43586WriteTokenFilePrivateAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := writeTokenFile(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "token" {
		t.Fatalf("directory entries = %v, want only token", entries)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Fatalf("token permissions = %o, want 644", perm)
	}
}
