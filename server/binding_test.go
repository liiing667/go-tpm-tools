package server

import (
	"crypto"
	"errors"
	"testing"

	"github.com/google/go-tpm-tools/attest/binding"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
)

func TestVerifyAttestationBindsChallengeToMachineAndConclusion(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	oldAK, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("create first AK: %v", err)
	}
	defer oldAK.Close()

	newMachineAK, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("create second AK: %v", err)
	}
	defer newMachineAK.Close()

	challengeNonce := []byte("challenge-nonce-43584")
	oldAttestation, err := oldAK.Attest(client.AttestOpts{Nonce: challengeNonce})
	if err != nil {
		t.Fatalf("first Attest(): %v", err)
	}

	registry := binding.NewRegistry()
	opts := VerifyOpts{
		Nonce:           challengeNonce,
		ChallengeID:     "projects/p/locations/l/challenges/challenge-1",
		TrustedAKs:      []crypto.PublicKey{oldAK.PublicKey(), newMachineAK.PublicKey()},
		BindingRegistry: registry,
		AllowSHA1:       true,
	}

	state, err := VerifyAttestation(oldAttestation, opts)
	if err != nil {
		t.Fatalf("first VerifyAttestation(): %v", err)
	}

	// A proof retry carries the same challenge and the same machine. It must
	// recover the existing conclusion rather than create a competing binding.
	if _, err := VerifyAttestation(oldAttestation, opts); err != nil {
		t.Fatalf("identical proof retry should recover its binding: %v", err)
	}
	oldMachine, err := AttestationMachineIdentity(oldAttestation, oldAK.PublicKey(), state)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := registry.Recover(
		binding.Challenge{ID: opts.ChallengeID, Nonce: challengeNonce}, oldMachine)
	if err != nil {
		t.Fatalf("Recover() old binding: %v", err)
	}
	if recovered.Generation != 1 || !recovered.Replayed {
		t.Fatalf("recovered binding = generation %d replayed %v, want 1/true",
			recovered.Generation, recovered.Replayed)
	}

	// A new request that accidentally reuses the old challenge nonce/resource
	// but is signed by another machine must not become the same authentication.
	otherAttestation, err := newMachineAK.Attest(client.AttestOpts{Nonce: challengeNonce})
	if err != nil {
		t.Fatalf("second machine Attest() with reused nonce: %v", err)
	}
	_, err = VerifyAttestation(otherAttestation, opts)
	if !errors.Is(err, binding.ErrMachineMismatch) {
		t.Fatalf("reused challenge with new machine error = %v, want ErrMachineMismatch", err)
	}

	// A normal reconnect creates a fresh challenge/nonce. The same machine is
	// allowed, but receives a distinct generation and authentication identity.
	reconnectNonce := []byte("reconnect-nonce-43584")
	reconnectAttestation, err := oldAK.Attest(client.AttestOpts{Nonce: reconnectNonce})
	if err != nil {
		t.Fatalf("reconnect Attest(): %v", err)
	}
	reconnectOpts := opts
	reconnectOpts.Nonce = reconnectNonce
	reconnectOpts.ChallengeID = "projects/p/locations/l/challenges/challenge-2"
	reconnectState, err := VerifyAttestation(reconnectAttestation, reconnectOpts)
	if err != nil {
		t.Fatalf("normal reconnect with a new challenge was blocked: %v", err)
	}
	reconnectMachine, err := AttestationMachineIdentity(reconnectAttestation, oldAK.PublicKey(), reconnectState)
	if err != nil {
		t.Fatal(err)
	}
	reconnected, err := registry.Recover(
		binding.Challenge{ID: reconnectOpts.ChallengeID, Nonce: reconnectNonce},
		reconnectMachine)
	if err != nil {
		t.Fatalf("Recover() reconnect binding: %v", err)
	}
	if reconnected.Generation != 2 {
		t.Fatalf("reconnect generation = %d, want 2", reconnected.Generation)
	}
	if reconnected.AuthenticationFingerprint == recovered.AuthenticationFingerprint {
		t.Fatal("reconnect reused the old authentication identity")
	}
}
