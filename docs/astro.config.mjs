import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://dshakes.github.io',
  base: '/halos',
  integrations: [
    starlight({
      title: 'Halos',
      description:
        'Ship AI coding tools like you ship software: versioned, signed, ring-deployed, and proven by evals.',
      logo: { src: './src/assets/logo.svg' },
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/dshakes/halos' },
      ],
      editLink: {
        baseUrl: 'https://github.com/dshakes/halos/edit/main/docs/',
      },
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        {
          label: 'Getting started',
          items: [
            'getting-started/introduction',
            'getting-started/playground',
            'getting-started/install',
            'getting-started/quickstart',
            'getting-started/installation',
          ],
        },
        {
          label: 'Concepts',
          items: [
            'concepts/how-it-works',
            'concepts/architecture',
            'concepts/simple-mode',
            'concepts/policy-model',
            'concepts/rings-and-releases',
            'concepts/rollouts',
            'concepts/experiments',
            'concepts/toggles',
            'concepts/evals',
            'concepts/shadow-traffic',
            'concepts/delivery',
            'concepts/self-service-portal',
            'concepts/stack-agnostic',
            'concepts/evidence-plane',
            'concepts/security-model',
          ],
        },
        {
          label: 'Tutorials',
          items: [
            { slug: 'tutorials', label: 'All tutorials' },
            'tutorials/first-10-minutes',
            'tutorials/claude-code-upgrade',
            'tutorials/canary-a-model',
            'tutorials/kill-a-bad-change',
            'tutorials/add-a-toggle',
            'tutorials/gate-upgrades-on-evals',
          ],
        },
        {
          label: 'Examples',
          items: [{ slug: 'examples', label: 'Example policy repos' }],
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
            'guides/reliable-upgrades',
            'guides/writing-evals',
            'guides/agentic-operations',
            'guides/production-deployment',
            'guides/new-harness-adapter',
          ],
        },
        {
          label: 'Reference',
          items: [
            {
              label: 'CLI',
              collapsed: true,
              items: [{ autogenerate: { directory: 'reference/cli' } }],
            },
            {
              label: 'Policy files',
              collapsed: true,
              items: [{ autogenerate: { directory: 'reference/policy' } }],
            },
            'reference/api',
            'reference/binaries',
            'reference/policy-schema',
            'reference/harness-matrix',
            'reference/metrics',
            'reference/gateway-headers',
            'reference/threat-model',
            'reference/faq',
            'reference/comparison',
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
            'adr/0010-release-channels-for-client-experiments',
          ],
        },
      ],
    }),
  ],
});
