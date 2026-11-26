// Package binding provides the immutable correlation contract between an
// attestation challenge, the machine identity that answers it, and the
// verifier conclusion produced for that exchange.
//
// A Registry is intentionally keyed by challenge, not by machine. As a
// result, retrying the same authentication recovers one conclusion, while a
// new challenge on reconnect starts a new generation for the same machine.
package binding

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// SchemaVersion is the current snapshot encoding version.
const SchemaVersion = "attestation-binding/v1"

// Verdict values for Conclusion.Verdict.
const (
	VerdictVerified = "verified"
	VerdictDenied   = "denied"
)

// Descriptive aliases for callers and review tools that use the security
// vocabulary from the challenge/machine/conclusion contract.
type (
	// Machine is the stable identity answering a challenge.
	Machine = MachineIdentity
	// Verdict is the final conclusion produced by a verifier.
	Verdict = Conclusion
	// AttestationBinding is the one-to-one-to-one correlation record.
	AttestationBinding = Binding
	// Ledger stores challenge-scoped attestation bindings.
	Ledger = Registry
)

// NewLedger is a descriptive alias for NewRegistry.
func NewLedger() *Ledger { return NewRegistry() }

var (
	// ErrEmptyChallenge means neither a challenge identifier nor nonce was supplied.
	ErrEmptyChallenge = errors.New("binding: challenge has no ID or nonce")
	// ErrEmptyMachineIdentity means the machine identity contains no usable field.
	ErrEmptyMachineIdentity = errors.New("binding: empty machine identity")
	// ErrEmptyConclusion means no conclusion identity material was supplied.
	ErrEmptyConclusion = errors.New("binding: empty conclusion")
	// ErrChallengeMismatch means a challenge key was reused with different challenge material.
	ErrChallengeMismatch = errors.New("binding: challenge identity mismatch")
	// ErrChallengeReplayed means one nonce was presented under two challenge keys.
	ErrChallengeReplayed = errors.New("binding: challenge nonce reused by another challenge")
	// ErrMachineMismatch means a challenge was answered by a different machine identity.
	ErrMachineMismatch = errors.New("binding: machine identity does not match challenge")
	// ErrConclusionMismatch means retry/recovery produced a different conclusion.
	ErrConclusionMismatch = errors.New("binding: conclusion does not match committed binding")
	// ErrConclusionNotCommitted means the challenge is known but has no conclusion yet.
	ErrConclusionNotCommitted = errors.New("binding: conclusion has not been committed")
	// ErrBindingNotFound means no session exists for the challenge and machine.
	ErrBindingNotFound = errors.New("binding: no binding found")
	// ErrInvalidSnapshot means persisted state failed consistency validation.
	ErrInvalidSnapshot = errors.New("binding: invalid snapshot")
)

// Fingerprint is a canonical, collision-resistant identity digest.
type Fingerprint string

func (f Fingerprint) String() string { return string(f) }

// Hash returns the domain-separated SHA-256 fingerprint of length-framed
// parts. Length framing prevents two adjacent fields from concatenating into
// the same digest as a different field grouping.
func Hash(parts ...[]byte) Fingerprint {
	h := sha256.New()
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(part)
	}
	return Fingerprint(hex.EncodeToString(h.Sum(nil)))
}

// Challenge identifies one verifier challenge. ID is normally the challenge
// resource name; Nonce is the cryptographic nonce embedded in the quote.
type Challenge struct {
	ID    string `json:"id,omitempty"`
	Nonce []byte `json:"nonce,omitempty"`
}

func (c Challenge) validate() error {
	if c.ID == "" && len(c.Nonce) == 0 {
		return ErrEmptyChallenge
	}
	return nil
}

// Key returns the stable registry key for the challenge. A resource ID takes
// precedence because it names the challenge; otherwise the nonce identifies it.
func (c Challenge) Key() (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	if c.ID != "" {
		return "id:" + c.ID, nil
	}
	return "nonce:" + c.NonceFingerprint().String(), nil
}

// NonceFingerprint returns the canonical nonce digest.
func (c Challenge) NonceFingerprint() Fingerprint {
	if len(c.Nonce) == 0 {
		return ""
	}
	return Hash([]byte("challenge-nonce/v1"), c.Nonce)
}

// Fingerprint binds the challenge ID and nonce together.
func (c Challenge) Fingerprint() Fingerprint {
	return Hash([]byte("challenge/v1"), []byte(c.ID), c.Nonce)
}

func challengesCompatible(recorded, supplied Challenge) error {
	if recorded.ID != "" && supplied.ID != "" && recorded.ID != supplied.ID {
		return fmt.Errorf("%w: challenge IDs %q and %q refer to different challenges: %w",
			ErrChallengeMismatch, recorded.ID, supplied.ID, ErrChallengeReplayed)
	}
	if len(recorded.Nonce) != 0 && len(supplied.Nonce) != 0 &&
		!bytes.Equal(recorded.Nonce, supplied.Nonce) {
		return fmt.Errorf("%w: challenge ID %q has a different nonce",
			ErrChallengeMismatch, firstNonEmpty(supplied.ID, recorded.ID))
	}
	return nil
}

func mergeChallenge(recorded *Challenge, supplied Challenge) {
	if len(recorded.Nonce) == 0 && len(supplied.Nonce) != 0 {
		recorded.Nonce = append([]byte(nil), supplied.Nonce...)
	}
	if recorded.ID == "" && supplied.ID != "" {
		recorded.ID = supplied.ID
	}
}

// InstanceIdentity is the GCE/instance portion of a machine identity.
type InstanceIdentity struct {
	ProjectNumber string `json:"project_number,omitempty"`
	ProjectID     string `json:"project_id,omitempty"`
	Zone          string `json:"zone,omitempty"`
	InstanceID    string `json:"instance_id,omitempty"`
	InstanceName  string `json:"instance_name,omitempty"`
}

// MachineIdentity contains the stable facts that identify the answering
// machine. Explicit ID may be a canonical instance resource name; the key and
// certificate DER fields cryptographically bind that identity to the quote.
type MachineIdentity struct {
	ID                 string            `json:"id,omitempty"`
	AKPublicKeyDER     []byte            `json:"ak_public_key_der,omitempty"`
	AKCertificateDER   []byte            `json:"ak_certificate_der,omitempty"`
	Instance           *InstanceIdentity `json:"instance,omitempty"`
	AdditionalEvidence map[string]string `json:"additional_evidence,omitempty"`
}

func (m MachineIdentity) isZero() bool {
	emptyInstance := m.Instance == nil || *m.Instance == (InstanceIdentity{})
	return m.ID == "" && len(m.AKPublicKeyDER) == 0 && len(m.AKCertificateDER) == 0 &&
		emptyInstance && len(m.AdditionalEvidence) == 0
}

// Validate reports whether the machine identity has at least one stable fact.
func (m MachineIdentity) Validate() error {
	if m.isZero() {
		return ErrEmptyMachineIdentity
	}
	return nil
}

// Fingerprint canonicalizes all machine identity facts.
func (m MachineIdentity) Fingerprint() Fingerprint {
	if m.isZero() {
		return ""
	}
	parts := [][]byte{[]byte("machine/v1"), []byte(m.ID), m.AKPublicKeyDER, m.AKCertificateDER}
	if m.Instance != nil {
		parts = append(parts,
			[]byte(m.Instance.ProjectNumber),
			[]byte(m.Instance.ProjectID),
			[]byte(m.Instance.Zone),
			[]byte(m.Instance.InstanceID),
			[]byte(m.Instance.InstanceName),
		)
	} else {
		// Keep field framing stable when the optional message is absent.
		parts = append(parts, nil, nil, nil, nil, nil)
	}
	// encoding/json gives deterministic map key ordering through its sorted-key
	// encoder. A marshalling failure for map[string]string is not expected.
	mapJSON, _ := json.Marshal(m.AdditionalEvidence)
	parts = append(parts, mapJSON)
	return Hash(parts...)
}

// Conclusion is the verifier's final result. Evidence should be a canonical
// representation of the verified state, token claims, or denial reason.
type Conclusion struct {
	ID       string `json:"id,omitempty"`
	Verdict  string `json:"verdict,omitempty"`
	Evidence []byte `json:"evidence,omitempty"`
}

func (c Conclusion) validate() error {
	if c.ID == "" && c.Verdict == "" && len(c.Evidence) == 0 {
		return ErrEmptyConclusion
	}
	return nil
}

// Fingerprint canonicalizes the conclusion identity.
func (c Conclusion) Fingerprint() Fingerprint {
	if err := c.validate(); err != nil {
		return ""
	}
	return Hash([]byte("conclusion/v1"), []byte(c.ID), []byte(c.Verdict), c.Evidence)
}

// Binding is the immutable one-to-one-to-one record for one authentication.
type Binding struct {
	Schema                    string          `json:"schema"`
	Generation                uint64          `json:"generation"`
	Challenge                 Challenge       `json:"challenge"`
	ChallengeKey              string          `json:"challenge_key"`
	ChallengeFingerprint      Fingerprint     `json:"challenge_fingerprint"`
	NonceFingerprint          Fingerprint     `json:"nonce_fingerprint,omitempty"`
	Machine                   MachineIdentity `json:"machine"`
	MachineFingerprint        Fingerprint     `json:"machine_fingerprint"`
	Conclusion                Conclusion      `json:"conclusion"`
	ConclusionFingerprint     Fingerprint     `json:"conclusion_fingerprint"`
	AuthenticationFingerprint Fingerprint     `json:"authentication_fingerprint"`

	// Replayed is true when the returned binding was recovered from an earlier
	// identical commit rather than newly created. It is not part of identity.
	Replayed bool `json:"-"`
}

// Matches reports whether b is the binding for the supplied challenge and
// machine. It is useful when an old receipt or recovered record is presented
// to a later request.
func (b Binding) Matches(challenge Challenge, machine MachineIdentity) error {
	key, err := challenge.Key()
	if err != nil {
		return err
	}
	if b.ChallengeKey != key {
		return fmt.Errorf("%w: binding challenge %q, request challenge %q",
			ErrChallengeMismatch, b.ChallengeKey, key)
	}
	if err := challengesCompatible(b.Challenge, challenge); err != nil {
		return err
	}
	if b.MachineFingerprint != machine.Fingerprint() {
		return fmt.Errorf("%w: binding %s, request %s",
			ErrMachineMismatch, b.MachineFingerprint, machine.Fingerprint())
	}
	return nil
}

type session struct {
	Challenge  Challenge
	Machine    MachineIdentity
	Generation uint64
	Binding    *Binding
}

// StoredSession is the serializable form of an in-progress or committed session.
type StoredSession struct {
	Challenge  Challenge       `json:"challenge"`
	Machine    MachineIdentity `json:"machine"`
	Generation uint64          `json:"generation"`
	Binding    *Binding        `json:"binding,omitempty"`
}

// Snapshot is a restartable registry image.
type Snapshot struct {
	Schema             string                 `json:"schema"`
	Sessions           []StoredSession        `json:"sessions"`
	MachineGenerations map[Fingerprint]uint64 `json:"machine_generations"`
}

// Registry correlates challenges, machines, and conclusions. Its methods are
// safe for concurrent use.
type Registry struct {
	mu         sync.Mutex
	sessions   map[string]*session
	ids        map[string]string
	nonces     map[Fingerprint]string
	machineGen map[Fingerprint]uint64
}

// NewRegistry creates an empty correlation registry.
func NewRegistry() *Registry {
	return &Registry{
		sessions:   make(map[string]*session),
		ids:        make(map[string]string),
		nonces:     make(map[Fingerprint]string),
		machineGen: make(map[Fingerprint]uint64),
	}
}

// resolveKeyLocked maps an equivalent ID-only, nonce-only, or ID+nonce
// representation to the canonical session key.
func (r *Registry) resolveKeyLocked(key string, challenge Challenge) string {
	if _, ok := r.sessions[key]; ok {
		return key
	}
	if challenge.ID != "" {
		if aliased, ok := r.ids[challenge.ID]; ok {
			return aliased
		}
	}
	if fp := challenge.NonceFingerprint(); fp != "" {
		if aliased, ok := r.nonces[fp]; ok {
			return aliased
		}
	}
	return key
}

// Start opens or recovers the session for a challenge/machine pair. Repeating
// Start with the same pair is idempotent. Presenting the same challenge to a
// different machine fails closed. A new challenge for the same machine starts
// the next reconnect generation.
func (r *Registry) Start(challenge Challenge, machine MachineIdentity) (uint64, error) {
	if r == nil {
		return 0, fmt.Errorf("binding: nil registry")
	}
	if err := challenge.validate(); err != nil {
		return 0, err
	}
	if err := machine.Validate(); err != nil {
		return 0, err
	}
	machine = cloneMachine(machine)
	key, err := challenge.Key()
	if err != nil {
		return 0, err
	}
	nonceFP := challenge.NonceFingerprint()

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions == nil {
		r.sessions = make(map[string]*session)
		r.ids = make(map[string]string)
		r.nonces = make(map[Fingerprint]string)
		r.machineGen = make(map[Fingerprint]uint64)
	}
	key = r.resolveKeyLocked(key, challenge)

	if nonceFP != "" {
		if other, ok := r.nonces[nonceFP]; ok && other != key {
			return 0, fmt.Errorf("%w: nonce already bound to %q, attempted %q",
				ErrChallengeReplayed, other, key)
		}
	}

	s, ok := r.sessions[key]
	if !ok {
		machineFP := machine.Fingerprint()
		r.machineGen[machineFP]++
		gen := r.machineGen[machineFP]
		cpChallenge := cloneChallenge(challenge)
		s = &session{
			Challenge:  cpChallenge,
			Machine:    machine,
			Generation: gen,
		}
		r.sessions[key] = s
		if challenge.ID != "" {
			r.ids[challenge.ID] = key
		}
		if nonceFP != "" {
			r.nonces[nonceFP] = key
		}
		return gen, nil
	}

	if err := challengesCompatible(s.Challenge, challenge); err != nil {
		return 0, err
	}
	if s.Machine.Fingerprint() != machine.Fingerprint() {
		return 0, fmt.Errorf("%w: challenge %q was opened by %s, got %s",
			ErrMachineMismatch, key, s.Machine.Fingerprint(), machine.Fingerprint())
	}
	mergeChallenge(&s.Challenge, challenge)
	if s.Challenge.ID != "" {
		r.ids[s.Challenge.ID] = key
	}
	if nonceFP := s.Challenge.NonceFingerprint(); nonceFP != "" {
		r.nonces[nonceFP] = key
	}
	return s.Generation, nil
}

// Begin is an alias for Start.
func (r *Registry) Begin(challenge Challenge, machine MachineIdentity) (uint64, error) {
	return r.Start(challenge, machine)
}

// Commit binds the conclusion to the challenge and machine. An identical
// retry returns the stored binding with Replayed=true. A different conclusion
// for the same challenge/machine is rejected.
func (r *Registry) Commit(challenge Challenge, machine MachineIdentity, conclusion Conclusion) (Binding, error) {
	if err := conclusion.validate(); err != nil {
		return Binding{}, err
	}
	conclusion = cloneConclusion(conclusion)
	gen, err := r.Start(challenge, machine)
	if err != nil {
		return Binding{}, err
	}
	key, _ := challenge.Key()

	r.mu.Lock()
	defer r.mu.Unlock()
	key = r.resolveKeyLocked(key, challenge)
	s := r.sessions[key]
	if s == nil {
		// Start created it unless state was concurrently restored or corrupted.
		return Binding{}, ErrBindingNotFound
	}
	if s.Binding != nil {
		if s.Binding.ConclusionFingerprint != conclusion.Fingerprint() {
			return Binding{}, fmt.Errorf("%w: stored %s, attempted %s",
				ErrConclusionMismatch, s.Binding.ConclusionFingerprint, conclusion.Fingerprint())
		}
		b := cloneBinding(*s.Binding)
		b.Replayed = true
		return b, nil
	}

	// Use the merged challenge stored in the session so a Start call that only
	// supplied the ID and a Commit call that supplied ID+nonce converge.
	completeChallenge := cloneChallenge(s.Challenge)
	challengeFP := completeChallenge.Fingerprint()
	nonceFP := completeChallenge.NonceFingerprint()
	machineFP := s.Machine.Fingerprint()
	conclusionFP := conclusion.Fingerprint()
	authFP := Hash(
		[]byte("authentication/v1"),
		[]byte(key),
		[]byte(challengeFP),
		[]byte(machineFP),
		[]byte(conclusionFP),
		uint64Bytes(gen),
	)
	b := &Binding{
		Schema:                    SchemaVersion,
		Generation:                gen,
		Challenge:                 completeChallenge,
		ChallengeKey:              key,
		ChallengeFingerprint:      challengeFP,
		NonceFingerprint:          nonceFP,
		Machine:                   s.Machine,
		MachineFingerprint:        machineFP,
		Conclusion:                conclusion,
		ConclusionFingerprint:     conclusionFP,
		AuthenticationFingerprint: authFP,
	}
	stored := cloneBinding(*b)
	s.Binding = &stored

	// Return a value copy; callers cannot mutate registry state through it.
	return cloneBinding(*b), nil
}

// Complete is an alias for Commit.
func (r *Registry) Complete(challenge Challenge, machine MachineIdentity, conclusion Conclusion) (Binding, error) {
	return r.Commit(challenge, machine, conclusion)
}

// Recover returns the committed conclusion for this challenge and machine.
// It never invents or recomputes a conclusion.
func (r *Registry) Recover(challenge Challenge, machine MachineIdentity) (Binding, error) {
	if r == nil {
		return Binding{}, fmt.Errorf("binding: nil registry")
	}
	key, err := challenge.Key()
	if err != nil {
		return Binding{}, err
	}
	if err := machine.Validate(); err != nil {
		return Binding{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	key = r.resolveKeyLocked(key, challenge)
	s, ok := r.sessions[key]
	if !ok {
		return Binding{}, fmt.Errorf("%w: challenge %q", ErrBindingNotFound, key)
	}
	if err := challengesCompatible(s.Challenge, challenge); err != nil {
		return Binding{}, err
	}
	if s.Machine.Fingerprint() != machine.Fingerprint() {
		return Binding{}, fmt.Errorf("%w: challenge %q was committed by %s, recovery requested by %s",
			ErrMachineMismatch, key, s.Machine.Fingerprint(), machine.Fingerprint())
	}
	if s.Binding == nil {
		return Binding{}, fmt.Errorf("%w: challenge %q", ErrConclusionNotCommitted, key)
	}
	b := cloneBinding(*s.Binding)
	b.Replayed = true
	return b, nil
}

// Verify recovers the binding and additionally requires the supplied
// conclusion to be exactly the committed one.
func (r *Registry) Verify(challenge Challenge, machine MachineIdentity, conclusion Conclusion) (Binding, error) {
	if err := conclusion.validate(); err != nil {
		return Binding{}, err
	}
	b, err := r.Recover(challenge, machine)
	if err != nil {
		return Binding{}, err
	}
	if b.ConclusionFingerprint != conclusion.Fingerprint() {
		return Binding{}, fmt.Errorf("%w: stored %s, supplied %s",
			ErrConclusionMismatch, b.ConclusionFingerprint, conclusion.Fingerprint())
	}
	return b, nil
}

// Snapshot returns a JSON-serializable point-in-time copy of the registry.
func (r *Registry) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()

	snap := Snapshot{
		Schema:             SchemaVersion,
		Sessions:           make([]StoredSession, 0, len(r.sessions)),
		MachineGenerations: make(map[Fingerprint]uint64, len(r.machineGen)),
	}
	for _, s := range r.sessions {
		ss := StoredSession{
			Challenge:  cloneChallenge(s.Challenge),
			Machine:    cloneMachine(s.Machine),
			Generation: s.Generation,
		}
		if s.Binding != nil {
			b := cloneBinding(*s.Binding)
			ss.Binding = &b
		}
		snap.Sessions = append(snap.Sessions, ss)
	}
	for k, v := range r.machineGen {
		snap.MachineGenerations[k] = v
	}
	return snap
}

// MarshalSnapshot encodes a registry snapshot as indented JSON.
func (r *Registry) MarshalSnapshot() ([]byte, error) {
	return json.MarshalIndent(r.Snapshot(), "", "  ")
}

// RestoreRegistry reconstructs a registry from a snapshot. Corrupt or
// internally inconsistent snapshots are rejected rather than partially used.
func RestoreRegistry(snap Snapshot) (*Registry, error) {
	if snap.Schema != SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported schema %q", ErrInvalidSnapshot, snap.Schema)
	}
	r := NewRegistry()
	for _, ss := range snap.Sessions {
		if err := ss.Challenge.validate(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
		}
		if err := ss.Machine.Validate(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
		}
		key, err := ss.Challenge.Key()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
		}
		if _, exists := r.sessions[key]; exists {
			return nil, fmt.Errorf("%w: duplicate challenge key %q", ErrInvalidSnapshot, key)
		}
		if ss.Challenge.ID != "" {
			if other, ok := r.ids[ss.Challenge.ID]; ok && other != key {
				return nil, fmt.Errorf("%w: challenge ID index conflict", ErrInvalidSnapshot)
			}
			r.ids[ss.Challenge.ID] = key
		}
		machineFP := ss.Machine.Fingerprint()
		if ss.Generation == 0 {
			return nil, fmt.Errorf("%w: zero generation for %q", ErrInvalidSnapshot, key)
		}
		if old := r.machineGen[machineFP]; ss.Generation > old {
			r.machineGen[machineFP] = ss.Generation
		}
		nonceFP := ss.Challenge.NonceFingerprint()
		if nonceFP != "" {
			if other, ok := r.nonces[nonceFP]; ok && other != key {
				return nil, fmt.Errorf("%w: nonce index conflict", ErrInvalidSnapshot)
			}
			r.nonces[nonceFP] = key
		}
		stored := &session{
			Challenge:  cloneChallenge(ss.Challenge),
			Machine:    cloneMachine(ss.Machine),
			Generation: ss.Generation,
		}
		if ss.Binding != nil {
			b := cloneBinding(*ss.Binding)
			if b.Schema != SchemaVersion || b.ChallengeKey != key ||
				b.MachineFingerprint != machineFP || b.Generation != ss.Generation {
				return nil, fmt.Errorf("%w: binding/session mismatch for %q", ErrInvalidSnapshot, key)
			}
			b.Machine = cloneMachine(stored.Machine)
			stored.Binding = &b
		}
		r.sessions[key] = stored
	}
	return r, nil
}

// UnmarshalRegistry decodes and validates a JSON snapshot.
func UnmarshalRegistry(data []byte) (*Registry, error) {
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
	}
	return RestoreRegistry(snap)
}

// WriteSnapshotFile atomically writes the registry snapshot to path. The file
// is owner-only because instance identity evidence can be sensitive.
func WriteSnapshotFile(path string, r *Registry) error {
	data, err := r.MarshalSnapshot()
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, data, 0o600)
}

// ReadSnapshotFile loads a registry snapshot. A missing file returns an empty
// registry so first reconnect after restart behaves like first start.
func ReadSnapshotFile(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewRegistry(), nil
	}
	if err != nil {
		return nil, err
	}
	return UnmarshalRegistry(data)
}

// WriteFileAtomic writes data to path via a same-directory temp file and rename.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".binding-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func cloneChallenge(c Challenge) Challenge {
	cp := c
	if c.Nonce != nil {
		cp.Nonce = append([]byte(nil), c.Nonce...)
	}
	return cp
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func cloneMachine(m MachineIdentity) MachineIdentity {
	cp := m
	cp.AKPublicKeyDER = cloneBytes(m.AKPublicKeyDER)
	cp.AKCertificateDER = cloneBytes(m.AKCertificateDER)
	if m.Instance != nil {
		instance := *m.Instance
		cp.Instance = &instance
	}
	if m.AdditionalEvidence != nil {
		cp.AdditionalEvidence = make(map[string]string, len(m.AdditionalEvidence))
		for k, v := range m.AdditionalEvidence {
			cp.AdditionalEvidence[k] = v
		}
	}
	return cp
}

func cloneConclusion(c Conclusion) Conclusion {
	cp := c
	cp.Evidence = cloneBytes(c.Evidence)
	return cp
}

func cloneBinding(b Binding) Binding {
	cp := b
	cp.Challenge = cloneChallenge(b.Challenge)
	cp.Machine = cloneMachine(b.Machine)
	cp.Conclusion = cloneConclusion(b.Conclusion)
	return cp
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func uint64Bytes(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}
