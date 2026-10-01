# Envoy

`envoy.yaml` is a static bootstrap: listener `:10000` -> cluster `halo_proxy` (STRICT_DNS). Two
settings matter for LLM traffic: route `timeout: 0s` (the 15s default route timeout kills streams) and
`stream_idle_timeout` (idle between chunks). Envoy does not buffer responses by default.

For Istio/Gateway API/Contour, express the same: route to the halo-proxy Service, disable the route
timeout, raise the idle timeout. halo-proxy sets `X-Forwarded-For` from its peer, so in mode (b) it
sees Envoy's address; use `trusted_header` + `trustedProxyCIDRs` only if Envoy sets the identity header
itself (e.g. from a `jwt_authn` filter's `payload_in_metadata` / `claim_to_headers`) and clients cannot.

Checked: `envoy --mode validate -c envoy.yaml` (v1.32) -> "OK". Not checked: live traffic.
