# v1alpha1 copy of examples/acme-corp

Used only by the CI jobs that install a **released** `halo` (`action`, `gitlab`):
the pinned release predates `apiVersion: halos.dev/v1`, so it can only validate
v1alpha1. This is the YAML of `examples/acme-corp` with every `apiVersion` rewritten and
nothing else changed; `TestV1Alpha1FixtureMirrorsExample` in `internal/policy`
fails if the two drift. Delete it and point both jobs back at `examples/acme-corp`
once the pinned release understands v1.
