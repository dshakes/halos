import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import mermaid from 'astro-mermaid';

export default defineConfig({
  site: 'https://halos-dev.github.io',
  base: '/halos',
  integrations: [
    mermaid({ theme: 'default', autoTheme: true }),
    starlight({
      title: 'Halos',
      description:
        'Ship AI coding tools like you ship software: versioned, signed, ring-deployed, and proven by evals.',
      logo: { src: './src/assets/logo.svg' },
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/halos-dev/halos' },
      ],
      editLink: {
        baseUrl: 'https://github.com/halos-dev/halos/edit/main/docs/',
      },
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        {
          label: 'Getting started',
          items: [
            'getting-started/introduction',
            'getting-started/quickstart',
            'getting-started/installation',
          ],
        },
        {
          label: 'Concepts',
          items: [
            'concepts/architecture',
            'concepts/policy-model',
            'concepts/rings-and-releases',
            'concepts/experiments',
            'concepts/shadow-traffic',
            'concepts/delivery',
            'concepts/self-service-portal',
            'concepts/stack-agnostic',
            'concepts/evidence-plane',
            'concepts/security-model',
          ],
        },
        {
          label: 'Guides',
          items: [
            'guides/bedrock-via-kong',
            'guides/direct-anthropic',
            'guides/dev-containers',
            'guides/coder-workspaces',
            'guides/laptops-mdm',
            'guides/cli-upgrade-ab',
            'guides/model-upgrade-canary',
            'guides/writing-evals',
            'guides/agentic-operations',
            'guides/production-deployment',
            'guides/new-harness-adapter',
          ],
        },
        {
          label: 'Reference',
          items: [
            'reference/cli',
            'reference/api',
            'reference/policy-schema',
            'reference/harness-matrix',
            'reference/metrics',
            'reference/gateway-headers',
            'reference/threat-model',
            'reference/faq',
          ],
        },
        {
          label: 'ADRs',
          items: [
            'adr',
            'adr/0001-environment-as-policy',
            'adr/0002-rings-point-at-immutable-releases',
            'adr/0003-experiments-on-traffic-plane-first',
            'adr/0004-shadow-single-turn-only',
            'adr/0005-signed-oci-bundles',
            'adr/0006-go-and-kong-go-pdk',
            'adr/0007-guardrails-in-go-not-opa',
            'adr/0008-signed-ring-pointers-and-verified-artifacts',
            'adr/0009-signed-kill-switch',
          ],
        },
      ],
    }),
  ],
});
