# DualCard TLC Artifact

`DualCard.tla` is a bounded model of identity-card registration, authorization-context issuance, activation, revocation, rule binding, and audit events. The scope is intentionally restricted to the abstract authorization-context state machine.

The model checks type safety, identity-card uniqueness, active-context ownership and status, globally unique context membership, owner-map consistency, audit traceability, and a rule-isolation property. `Revoke` selects only an `ACTIVE` replacement context or `NULL`.

It does not model access JWT issuance, refresh sessions, Redis projections, gateway forwarding, outbox recovery, or distributed failures. Those guarantees require the Docker protocol evidence suite and must not be inferred from TLC output.

Build a runner image with an immutable base image and a verified TLC checksum, for example:

```bash
docker build formal \
  --build-arg BASE_IMAGE="${TDSC_TLC_BASE_IMAGE:?}" \
  --build-arg TLA2TOOLS_SHA256="${TDSC_TLA2TOOLS_SHA256:?}" \
  --tag "${TDSC_TLC_LOCAL_TAG:?}"
```

Resolve the built image to a digest, export it as `TDSC_TLC_IMAGE`, then run:

```bash
TDSC_TLC_IMAGE="${TDSC_TLC_IMAGE:?}" ./formal/run-tlc.sh
```

The runner writes an ignored `results/<run-id>/` directory containing the copied module/configuration, exact command, Git revision, image reference, unedited stdout/stderr, exit status, and checksums. A nonzero TLC exit leaves this evidence intact and fails the command.
