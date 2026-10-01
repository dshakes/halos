# AWS API Gateway  (UNVERIFIED: not imported into an AWS account)

`openapi.yaml`: an HTTP API with a catch-all `ANY /{proxy+}` route -> VPC link -> internal ALB (or NLB)
-> halo-proxy on ECS/EKS/EC2. Fill `ALB_DNS_NAME`, `VPC_LINK_ID`.

**Limits to check before choosing this** (from AWS documentation as understood, not verified here):
- HTTP APIs cap integration timeout at 30 s and do not stream responses, so long agent turns and
  SSE will fail or arrive in one piece. REST APIs have added response streaming with longer timeouts;
  confirm current quotas for your region.
- If long streams matter, put the ALB/NLB directly in front of halo-proxy and use API Gateway only for
  non-streaming calls, or skip it for model traffic.
- Anthropic-style clients send the alias in the JSON body; Bedrock-style clients put it in the path
  (`/model/<alias>/invoke`). Aliases contain no reserved characters, so `{proxy+}` passes them through.

Auth: a Lambda/JWT authorizer would consume the token; halo-proxy still needs it (forward
`Authorization` to the integration) or use `trusted_header` with the VPC link's source CIDRs
(request parameter mapping `overwrite:header.x-user = $context.authorizer.claims.email`).
