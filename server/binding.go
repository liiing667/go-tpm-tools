package server

import (
	"crypto"
	"fmt"
	"strconv"

	"github.com/google/go-tpm-tools/attest/binding"
	pb "github.com/google/go-tpm-tools/proto/attest"
	"google.golang.org/protobuf/proto"
)

// AttestationMachineIdentity derives the stable machine identity used for
// challenge correlation. The quote signing key is authoritative; GCE instance
// metadata from the validated AK certificate is attached when present.
func AttestationMachineIdentity(attestation *pb.Attestation, akPub crypto.PublicKey, state *pb.MachineState) (binding.MachineIdentity, error) {
	machine, err := binding.MachineIdentityFromPublicKey(akPub, nil)
	if err != nil {
		return binding.MachineIdentity{}, err
	}
	if attestation != nil && len(attestation.GetAkCert()) != 0 {
		machine.AKCertificateDER = append([]byte(nil), attestation.GetAkCert()...)
	}

	if info := state.GetPlatform().GetInstanceInfo(); info != nil {
		machine.Instance = &binding.InstanceIdentity{
			ProjectNumber: strconv.FormatUint(info.GetProjectNumber(), 10),
			ProjectID:     info.GetProjectId(),
			Zone:          info.GetZone(),
			InstanceID:    strconv.FormatUint(info.GetInstanceId(), 10),
			InstanceName:  info.GetInstanceName(),
		}
		if info.GetProjectNumber() != 0 && info.GetZone() != "" && info.GetInstanceId() != 0 {
			machine.ID = fmt.Sprintf("projects/%d/zones/%s/instances/%d",
				info.GetProjectNumber(), info.GetZone(), info.GetInstanceId())
		}
	}
	return machine, nil
}

// AttestationConclusion canonicalizes the verified MachineState as the
// verifier conclusion.
func AttestationConclusion(state *pb.MachineState) (binding.Conclusion, error) {
	evidence, err := proto.MarshalOptions{Deterministic: true}.Marshal(state)
	if err != nil {
		return binding.Conclusion{}, fmt.Errorf("marshal verified MachineState for binding: %w", err)
	}
	return binding.Conclusion{Verdict: binding.VerdictVerified, Evidence: evidence}, nil
}

func commitAttestationConclusion(opts VerifyOpts, machine binding.MachineIdentity, state *pb.MachineState) error {
	if opts.BindingRegistry == nil {
		return nil
	}

	conclusion, err := AttestationConclusion(state)
	if err != nil {
		return err
	}
	challenge := binding.Challenge{ID: opts.ChallengeID, Nonce: append([]byte(nil), opts.Nonce...)}
	if _, err := opts.BindingRegistry.Commit(challenge, machine, conclusion); err != nil {
		return fmt.Errorf("attestation challenge/machine/conclusion correlation failed: %w", err)
	}
	return nil
}
