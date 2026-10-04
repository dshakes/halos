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
      logo: { light: './src/assets/logo-light.svg', dark: './src/assets/logo-dark.svg' },
      favicon: '/favicon.svg',
      head: [
        { tag: 'meta', attrs: { property: 'og:image', content: 'https://dshakes.github.io/halos/og.png' } },
        { tag: 'meta', attrs: { property: 'og:image:width', content: '1200' } },
        { tag: 'meta', attrs: { property: 'og:image:height', content: '630' } },
        { tag: 'meta', attrs: { name: 'twitter:image', content: 'https://dshakes.github.io/halos/og.png' } },
      ],
      expressiveCode: {
        themes: ['github-dark-default', 'github-light'],
        styleOverrides: {
          borderRadius: '12px',
          borderColor: 'var(--sl-color-hairline-light)',
          codeFontFamily: 'var(--sl-font-mono)',
          codeFontSize: '0.86rem',
          codeLineHeight: '1.7',
          uiFontFamily: 'var(--sl-font)',
          // Warm ink / paper instead of GitHub's blue-black, to match the Eclipse tokens.
          codeBackground: ({ theme }) => (theme.type === 'dark' ? '#0e0e12' : '#fffdf9'),
          frames: {
            shadowColor: 'transparent',
            frameBoxShadowCssValue: 'none',
            editorTabBarBackground: ({ theme }) => (theme.type === 'dark' ? '#121217' : '#f3ece0'),
            editorActiveTabBackground: ({ theme }) => (theme.type === 'dark' ? '#0e0e12' : '#fffdf9'),
            terminalTitlebarBackground: ({ theme }) => (theme.type === 'dark' ? '#121217' : '#f3ece0'),
            terminalBackground: ({ theme }) => (theme.type === 'dark' ? '#0e0e12' : '#fffdf9'),
          },
        },
      },
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/dshakes/halos' },
      ],
      editLink: {
        baseUrl: 'https://github.com/dshakes/halos/edit/main/docs/',
      },
      customCss: [
        '@fontsource-variable/inter/wght.css',
        '@fontsource-variable/jetbrains-mono/wght.css',
        '@fontsource-variable/sora/wght.css',
        './src/styles/tokens.css',
        './src/styles/custom.css',
      ],
      components: { SiteTitle: './src/components/SiteTitle.astro' },
      // Start here -> Getting started -> Concepts -> Guides -> Reference -> ADRs.
      // Every page is listed exactly once; new pages must be added here or they are orphans.
      sidebar: [
        { slug: 'getting-started/start-here' },
        {
          label: 'Getting started',
          items: [
            { slug: 'getting-started/install', label: 'Install halo' },
            { slug: 'getting-started/playground', label: 'Try it: the playground' },
            { slug: 'tutorials/first-10-minutes', label: 'Your first 10 minutes' },
            { slug: 'getting-started/quickstart', label: 'Quickstart by hand' },
            { slug: 'getting-started/introduction', label: 'What Halos is' },
            { slug: 'examples', label: 'Example policy repos' },
          ],
        },
        {
          label: 'Concepts',
          items: [
            'concepts/how-it-works',
            'concepts/architecture',
            'concepts/policy-model',
            'concepts/simple-mode',
            'concepts/rings-and-releases',
            'concepts/rollouts',
            'concepts/experiments',
            'concepts/toggles',
            'concepts/evals',
            'concepts/shadow-traffic',
            'concepts/delivery',
            'concepts/self-service-portal',
            'concepts/evidence-plane',
            'concepts/security-model',
            'concepts/stack-agnostic',
            {
              label: 'Architecture deep dive',
              collapsed: true,
              items: ['architecture/components', 'architecture/low-level-design', 'architecture/tech-stack'],
            },
          ],
        },
        {
          label: 'Guides',
          items: [
            {
              label: 'Tutorials',
              items: [
                { slug: 'tutorials', label: 'All tutorials' },
                'tutorials/claude-code-upgrade',
                'tutorials/canary-a-model',
                'tutorials/kill-a-bad-change',
                'tutorials/add-a-toggle',
                'tutorials/gate-upgrades-on-evals',
              ],
            },
            {
              label: 'Roll out',
              items: [
                'guides/reliable-upgrades',
                'guides/cli-upgrade-ab',
                'guides/model-upgrade-canary',
                'guides/writing-evals',
                'guides/agentic-operations',
              ],
            },
            {
              label: 'Deliver to machines',
              items: ['guides/dev-containers', 'guides/coder-workspaces', 'guides/laptops-mdm'],
            },
            {
              label: 'Run the gateway',
              items: ['guides/bedrock-via-kong', 'guides/direct-anthropic', 'guides/provider-smoke'],
            },
            {
              label: 'Operate',
              items: ['guides/production-deployment', 'guides/operations', 'guides/new-harness-adapter'],
            },
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
            'reference/policy-schema',
            'reference/api',
            'reference/gateway-headers',
            'reference/metrics',
            'reference/binaries',
            { slug: 'getting-started/installation', label: 'Build from source' },
            'reference/harness-matrix',
            'reference/compatibility',
            'reference/support-policy',
            'reference/threat-model',
            'reference/comparison',
            'reference/faq',
          ],
        },
        {
          label: 'ADRs',
          collapsed: true,
          items: [{ autogenerate: { directory: 'adr' } }],
        },
      ],
    }),
  ],
});
