package agent

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm-tools/verifier"
)

type challengeSequenceClient struct {
	mu         sync.Mutex
	sequence   int
	challenges []*verifier.Challenge
	requests   []verifier.VerifyAttestationRequest
}

func (c *challengeSequenceClient) CreateChallenge(context.Context) (*verifier.Challenge, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sequence++
	challenge := &verifier.Challenge{
		Name:  fmt.Sprintf("projects/test/locations/test/challenges/ch-%d", c.sequence),
		Nonce: []byte(fmt.Sprintf("fresh-nonce-%d", c.sequence)),
	}
	c.challenges = append(c.challenges, challenge)
	return challenge, nil
}

func (c *challengeSequenceClient) VerifyAttestation(_ context.Context, req verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	return c.record(req), nil
}

func (c *challengeSequenceClient) VerifyConfidentialSpace(_ context.Context, req verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	return c.record(req), nil
}

func (c *challengeSequenceClient) record(req verifier.VerifyAttestationRequest) *verifier.VerifyAttestationResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, req)
	return &verifier.VerifyAttestationResponse{ClaimsToken: []byte("claims-token")}
}

func TestAttestAttemptsDoNotReuseChallengeState(t *testing.T) {
	ctx := context.Background()
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	verifierClient := &challengeSequenceClient{}
	a, err := CreateAttestationAgent(
		rwc,
		client.AttestationKeyECC,
		verifierClient,
		placeholderPrincipalFetcher,
		NewFakeClient(),
		Experiments{},
		SimpleLogger(),
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateAttestationAgent(): %v", err)
	}
	defer a.Close()

	for i := 0; i < 2; i++ {
		if _, err := a.Attest(ctx, AttestAgentOpts{}); err != nil {
			t.Fatalf("Attest attempt %d: %v", i+1, err)
		}
	}

	verifierClient.mu.Lock()
	defer verifierClient.mu.Unlock()

	if got := len(verifierClient.challenges); got != 2 {
		t.Fatalf("CreateChallenge calls = %d, want 2", got)
	}
	if got := len(verifierClient.requests); got != 2 {
		t.Fatalf("verify requests = %d, want 2", got)
	}

	first, second := verifierClient.challenges[0], verifierClient.challenges[1]
	if first.Name == second.Name {
		t.Fatalf("second attempt reused challenge name %q", first.Name)
	}
	if string(first.Nonce) == string(second.Nonce) {
		t.Fatalf("second attempt reused challenge nonce %q", first.Nonce)
	}

	for i, req := range verifierClient.requests {
		want := verifierClient.challenges[i]
		if req.Challenge != want {
			t.Fatalf("request %d challenge pointer = %p, want %p", i+1, req.Challenge, want)
		}
		if req.Challenge == nil || req.Challenge.Name != want.Name {
			t.Fatalf("request %d challenge = %+v, want %+v", i+1, req.Challenge, want)
		}
	}
}
