# Attestation challenge, machine, and conclusion binding

## Contract

One attestation authentication is the triple:

1. the verifier `Challenge` (resource ID and cryptographic nonce);
2. the stable `MachineIdentity` that answers it (quote-signing AK and, when
   present, its GCE instance metadata);
3. the verifier `Conclusion` for that exchange.

`attest/binding.Registry` stores that triple as one immutable
`AttestationBinding`. The registry is keyed by challenge, **not** by machine:

- Exact retry of challenge + machine + conclusion recovers the same binding.
- The same challenge presented by another machine is rejected.
- The same challenge/machine with another conclusion is rejected.
- One nonce cannot be registered under two challenge resource IDs.
- A new challenge/nonce on reconnect is a new generation for the same machine
  and is allowed.
- A recovered old receipt does not match a new challenge.

`server.VerifyOpts.BindingRegistry` connects this contract to
`server.VerifyAttestation`. When set, the verified AK/instance identity and
canonical `MachineState` conclusion are committed before verification returns.
A nil registry preserves the previous stateless library behavior.

## Recovery

`Registry.Snapshot` produces deterministic JSON. `WriteSnapshotFile` writes it
atomically with owner-only permissions; `ReadSnapshotFile` reloads it after a
process or node restart. Restore validates challenge keys, machine fingerprints,
generations, nonce indexes, and binding/session consistency before use.

## Compatibility

Existing callers do not set `VerifyOpts.BindingRegistry`, so their verification
flow and retry semantics remain unchanged. Normal reconnects continue to work
because they must request and use a fresh challenge; the registry never rejects
a new challenge merely because the machine identity was seen before.

## Regression evidence

`attest/binding` covers the one-to-one triple, identity drift, conclusion
conflict, nonce replay, normal reconnect, snapshot restart, file persistence,
concurrent identical retries, and concurrent machine takeover.
`server/binding_test.go` exercises the same contract through
`server.VerifyAttestation` with trusted TPM attestation keys.
