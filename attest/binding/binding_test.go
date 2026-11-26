package binding

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func testTriple(i int) (Challenge, MachineIdentity, Conclusion) {
	return Challenge{
		ID:    "projects/p/locations/l/challenges/ch-" + string(rune('a'+i)),
		Nonce: []byte("nonce-" + string(rune('a'+i))),
	}, MachineIdentity{
		ID: "projects/123/zones/z/instances/" + string(rune('1'+i)),
		Instance: &InstanceIdentity{
			ProjectNumber: "123",
			Zone:          "z",
			InstanceID:    string(rune('1' + i)),
		},
	}, Conclusion{
		Verdict:  VerdictVerified,
		Evidence: []byte("machine-state-" + string(rune('1'+i))),
	}
}

func TestCommitRecoveryIsOneToOne(t *testing.T) {
	r := NewRegistry()
	ch, machine, conclusion := testTriple(0)

	first, err := r.Commit(ch, machine, conclusion)
	if err != nil {
		t.Fatalf("first Commit() error = %v", err)
	}
	if first.Replayed {
		t.Fatal("first Commit() was marked replay")
	}
	if first.Generation != 1 {
		t.Fatalf("Generation = %d, want 1", first.Generation)
	}
	if first.AuthenticationFingerprint == "" || first.MachineFingerprint == "" ||
		first.ConclusionFingerprint == "" || first.ChallengeFingerprint == "" {
		t.Fatalf("binding is missing identity fingerprints: %+v", first)
	}

	// A proof retry with the exact same triple recovers the same conclusion.
	retry, err := r.Commit(ch, machine, conclusion)
	if err != nil {
		t.Fatalf("identical retry Commit() error = %v", err)
	}
	if !retry.Replayed {
		t.Fatal("identical retry was not marked replay")
	}
	if retry.AuthenticationFingerprint != first.AuthenticationFingerprint {
		t.Fatalf("retry authentication = %q, want %q",
			retry.AuthenticationFingerprint, first.AuthenticationFingerprint)
	}

	recovered, err := r.Recover(Challenge{ID: ch.ID}, machine)
	if err != nil {
		t.Fatalf("Recover() by challenge resource ID only error = %v", err)
	}
	if recovered.AuthenticationFingerprint != first.AuthenticationFingerprint {
		t.Fatalf("recovered authentication = %q, want %q",
			recovered.AuthenticationFingerprint, first.AuthenticationFingerprint)
	}

	nonceOnly := Challenge{Nonce: append([]byte(nil), ch.Nonce...)}
	recoveredByNonce, err := r.Recover(nonceOnly, machine)
	if err != nil {
		t.Fatalf("Recover() by nonce only error = %v", err)
	}
	if recoveredByNonce.AuthenticationFingerprint != first.AuthenticationFingerprint {
		t.Fatal("nonce-only recovery resolved to a different binding")
	}
	idOnlyRetry, err := r.Commit(Challenge{ID: ch.ID}, machine, conclusion)
	if err != nil {
		t.Fatalf("ID-only retry Commit() error = %v", err)
	}
	if !idOnlyRetry.Replayed || idOnlyRetry.AuthenticationFingerprint != first.AuthenticationFingerprint {
		t.Fatal("ID-only retry did not recover the original binding")
	}
	if _, err := r.Verify(ch, machine, conclusion); err != nil {
		t.Fatalf("Verify() same conclusion error = %v", err)
	}
}

func TestChallengeCannotBindAnotherMachineOrConclusion(t *testing.T) {
	r := NewRegistry()
	ch, machine, conclusion := testTriple(0)
	if _, err := r.Commit(ch, machine, conclusion); err != nil {
		t.Fatal(err)
	}

	otherMachine := MachineIdentity{ID: "machine-evil", AKPublicKeyDER: []byte("other-ak")}
	_, err := r.Commit(ch, otherMachine, conclusion)
	if !errors.Is(err, ErrMachineMismatch) {
		t.Fatalf("other machine Commit() error = %v, want ErrMachineMismatch", err)
	}
	_, err = r.Recover(ch, otherMachine)
	if !errors.Is(err, ErrMachineMismatch) {
		t.Fatalf("other machine Recover() error = %v, want ErrMachineMismatch", err)
	}

	otherConclusion := Conclusion{Verdict: VerdictVerified, Evidence: []byte("different-state")}
	_, err = r.Commit(ch, machine, otherConclusion)
	if !errors.Is(err, ErrConclusionMismatch) {
		t.Fatalf("different conclusion Commit() error = %v, want ErrConclusionMismatch", err)
	}
	_, err = r.Verify(ch, machine, otherConclusion)
	if !errors.Is(err, ErrConclusionMismatch) {
		t.Fatalf("Verify() different conclusion error = %v, want ErrConclusionMismatch", err)
	}

	wrongNonce := ch
	wrongNonce.Nonce = []byte("different-nonce")
	_, err = r.Recover(wrongNonce, machine)
	if !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("wrong nonce Recover() error = %v, want ErrChallengeMismatch", err)
	}

	replayedNonce := Challenge{ID: "challenge-new-request", Nonce: append([]byte(nil), ch.Nonce...)}
	_, err = r.Commit(replayedNonce, MachineIdentity{ID: "new-machine"}, conclusion)
	if !errors.Is(err, ErrChallengeReplayed) {
		t.Fatalf("nonce replay Commit() error = %v, want ErrChallengeReplayed", err)
	}
}

func TestStartBindsMachineBeforeConclusion(t *testing.T) {
	r := NewRegistry()
	ch, machine, _ := testTriple(0)

	gen, err := r.Start(ch, machine)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if gen != 1 {
		t.Fatalf("Start() generation = %d, want 1", gen)
	}
	if _, err := r.Recover(ch, machine); !errors.Is(err, ErrConclusionNotCommitted) {
		t.Fatalf("Recover() before commit error = %v, want ErrConclusionNotCommitted", err)
	}

	other := MachineIdentity{ID: "machine-takeover", AKPublicKeyDER: []byte("ak")}
	if _, err := r.Start(ch, other); !errors.Is(err, ErrMachineMismatch) {
		t.Fatalf("Start() other machine error = %v, want ErrMachineMismatch", err)
	}

	genAgain, err := r.Start(ch, machine)
	if err != nil {
		t.Fatalf("idempotent Start() error = %v", err)
	}
	if genAgain != gen {
		t.Fatalf("idempotent Start() generation = %d, want %d", genAgain, gen)
	}
}

func TestReconnectWithNewChallengeIsAllowedAndDistinct(t *testing.T) {
	r := NewRegistry()
	firstCh, machine, firstConclusion := testTriple(0)
	first, err := r.Commit(firstCh, machine, firstConclusion)
	if err != nil {
		t.Fatal(err)
	}

	secondCh := Challenge{ID: "challenges/reconnect", Nonce: []byte("fresh-reconnect-nonce")}
	secondConclusion := Conclusion{Verdict: VerdictVerified, Evidence: []byte("current-state")}
	second, err := r.Commit(secondCh, machine, secondConclusion)
	if err != nil {
		t.Fatalf("normal reconnect with a fresh challenge was blocked: %v", err)
	}
	if second.Generation != first.Generation+1 {
		t.Fatalf("reconnect Generation = %d, want %d", second.Generation, first.Generation+1)
	}
	if second.AuthenticationFingerprint == first.AuthenticationFingerprint {
		t.Fatal("reconnect reused the first authentication identity")
	}

	if err := first.Matches(secondCh, machine); !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("old receipt against new challenge error = %v, want ErrChallengeMismatch", err)
	}
	if err := second.Matches(secondCh, machine); err != nil {
		t.Fatalf("new binding does not match its own challenge: %v", err)
	}

	recovered, err := r.Recover(secondCh, machine)
	if err != nil {
		t.Fatalf("recover reconnect conclusion: %v", err)
	}
	if recovered.ConclusionFingerprint != second.ConclusionFingerprint {
		t.Fatal("reconnect recovery returned the wrong conclusion")
	}
	oldRecovered, err := r.Recover(firstCh, machine)
	if err != nil {
		t.Fatalf("old conclusion should remain recoverable for audit: %v", err)
	}
	if oldRecovered.AuthenticationFingerprint != first.AuthenticationFingerprint {
		t.Fatal("old challenge conclusion changed after reconnect")
	}
}

func TestSnapshotRestoresOneToOneState(t *testing.T) {
	r := NewRegistry()
	ch1, machine, c1 := testTriple(0)
	first, err := r.Commit(ch1, machine, c1)
	if err != nil {
		t.Fatal(err)
	}
	ch2 := Challenge{ID: "challenges/two", Nonce: []byte("nonce-two")}
	if _, err := r.Commit(ch2, machine, Conclusion{Verdict: VerdictVerified, Evidence: []byte("two")}); err != nil {
		t.Fatal(err)
	}

	data, err := r.MarshalSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalRegistry(data)
	if err != nil {
		t.Fatalf("UnmarshalRegistry() error = %v", err)
	}

	got, err := restored.Recover(ch1, machine)
	if err != nil {
		t.Fatalf("restored Recover() error = %v", err)
	}
	if got.AuthenticationFingerprint != first.AuthenticationFingerprint {
		t.Fatal("restored binding identity changed")
	}
	if _, err := restored.Commit(ch1, MachineIdentity{ID: "other"}, c1); !errors.Is(err, ErrMachineMismatch) {
		t.Fatalf("restored registry allowed identity drift: %v", err)
	}

	ch3 := Challenge{ID: "challenges/three", Nonce: []byte("nonce-three")}
	third, err := restored.Commit(ch3, machine, Conclusion{Verdict: VerdictVerified, Evidence: []byte("three")})
	if err != nil {
		t.Fatalf("new challenge after restore: %v", err)
	}
	if third.Generation != 3 {
		t.Fatalf("post-restore Generation = %d, want 3", third.Generation)
	}
}

func TestSnapshotFileMissingAndRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "bindings.json")
	r, err := ReadSnapshotFile(path)
	if err != nil {
		t.Fatalf("ReadSnapshotFile(missing) error = %v", err)
	}
	ch, m, c := testTriple(0)
	if _, err := r.Commit(ch, m, c); err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshotFile(path, r); err != nil {
		t.Fatalf("WriteSnapshotFile() error = %v", err)
	}
	r2, err := ReadSnapshotFile(path)
	if err != nil {
		t.Fatalf("ReadSnapshotFile() error = %v", err)
	}
	if _, err := r2.Recover(ch, m); err != nil {
		t.Fatalf("recovered file binding: %v", err)
	}
}

func TestConcurrentIdenticalCommitIsSingleBinding(t *testing.T) {
	r := NewRegistry()
	ch, m, c := testTriple(0)
	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	fps := make(chan Fingerprint, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := r.Commit(ch, m, c)
			if err != nil {
				errs <- err
				return
			}
			fps <- b.AuthenticationFingerprint
		}()
	}
	wg.Wait()
	close(errs)
	close(fps)
	for err := range errs {
		t.Error(err)
	}
	var want Fingerprint
	for fp := range fps {
		if want == "" {
			want = fp
		} else if fp != want {
			t.Fatalf("concurrent commits produced fingerprints %q and %q", want, fp)
		}
	}
}

func TestConcurrentMachineTakeoverIsRejected(t *testing.T) {
	r := NewRegistry()
	ch, _, c := testTriple(0)
	const n = 32
	var wg sync.WaitGroup
	var success, mismatch int64
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m := MachineIdentity{ID: "machine-" + string(rune('A'+i))}
			_, err := r.Commit(ch, m, c)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				success++
			case errors.Is(err, ErrMachineMismatch):
				mismatch++
			default:
				t.Errorf("Commit() unexpected error = %v", err)
			}
		}(i)
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("successful machine bindings = %d, want 1", success)
	}
	if mismatch != n-1 {
		t.Fatalf("machine mismatches = %d, want %d", mismatch, n-1)
	}
}

func TestMachineIdentityFromPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, err := MachineIdentityFromPublicKey(key.Public(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Fingerprint() == "" {
		t.Fatal("empty machine fingerprint")
	}

	other, err := MachineIdentityFromPublicKey(ecdsa.PublicKey{Curve: elliptic.P256(), X: key.X, Y: key.Y}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if other.Fingerprint() != m.Fingerprint() {
		t.Fatal("equivalent public keys gave different machine fingerprints")
	}
}

func TestEmptyValuesRejected(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Commit(Challenge{}, MachineIdentity{ID: "m"}, Conclusion{ID: "c"}); !errors.Is(err, ErrEmptyChallenge) {
		t.Errorf("empty challenge error = %v, want ErrEmptyChallenge", err)
	}
	if _, err := r.Commit(Challenge{ID: "c"}, MachineIdentity{}, Conclusion{ID: "x"}); !errors.Is(err, ErrEmptyMachineIdentity) {
		t.Errorf("empty machine error = %v, want ErrEmptyMachineIdentity", err)
	}
	if _, err := r.Commit(Challenge{ID: "c"}, MachineIdentity{ID: "m"}, Conclusion{}); !errors.Is(err, ErrEmptyConclusion) {
		t.Errorf("empty conclusion error = %v, want ErrEmptyConclusion", err)
	}
}
