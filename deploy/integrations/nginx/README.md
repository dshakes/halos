# nginx

`halo-proxy.conf` (include inside `http {}`) proxies the model paths to halo-proxy with
`proxy_buffering off`, HTTP/1.1 keep-alive and long timeouts so SSE stays incremental. `proxy_pass`
has no URI part on purpose: nginx then forwards the original encoded URI, which keeps Bedrock-style
`/model/<id>/invoke` paths intact.

If nginx authenticates clients (e.g. `auth_request`) and the JWT does not reach halo-proxy, use
`identity.mode: trusted_header` with `trustedProxyCIDRs` = nginx's address, and make nginx *set*
(not append) the identity header with `proxy_set_header`.

Checked: `nginx -t` (nginx:alpine, with `halo-proxy` resolvable). Not checked: live traffic.
