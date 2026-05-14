# DepGuard

> Universal dependency health scanner CLI for JavaScript ecosystems.

[![npm version](https://img.shields.io/npm/v/@lbharath/depguard)](https://www.npmjs.com/package/@lbharath/depguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

DepGuard scans any JavaScript or TypeScript project and gives you a complete
dependency health picture in a single command — outdated packages, known
vulnerabilities (via [OSV.dev](https://osv.dev)), deprecated libraries, and
abandoned/stale packages — across **npm, pnpm, yarn, bun**, and partial
**deno** support.

---

## Features

| Check | How |
|-------|-----|
| Outdated versions | `npm/pnpm/yarn/bun outdated` + semver diff |
| Vulnerabilities | `npm/pnpm/yarn audit` + OSV.dev batch API |
| Deprecated packages | npm registry (`deprecated` field) |
| Stale / unmaintained | npm registry publish timestamps (>24 months) |
| Monorepo workspaces | npm / pnpm / yarn / bun workspace patterns |
| CI failure mode | `--fail-on-high` exits with code 1 |

---

## Requirements

- **Node.js >= 18** (uses native `fetch` and `AbortSignal.timeout`)

---

## Installation

### Global install (recommended for local use)

```bash
npm install -g @lbharath/depguard
```

### One-off usage with npx (no install needed)

```bash
npx @lbharath/depguard
```

### Project dev dependency

```bash
npm install --save-dev @lbharath/depguard
# then in package.json scripts:
# "health": "depguard"
```

---

## Usage

### Basic scan (current directory)

```bash
depguard
```

### Scan a specific directory

```bash
depguard scan ./apps/web
depguard scan ./packages/api
```

### Security-only scan

```bash
depguard audit
```

### Deep scan (includes transitive dependencies)

```bash
depguard scan --deep
```

### Monorepo workspace scan

```bash
depguard --workspace
depguard scan --workspace
```

---

## Output Formats

### Terminal (default)

Human-readable coloured report with severity badges.

```
  DepGuard  —  Dependency Health Report
  ────────────────────────────────────────────────────────────
  Project         my-app
  Package Manager npm
  ...

  🔴  Vulnerabilities
  lodash@4.17.15
     CRITICAL   Prototype Pollution
                Affected: >=0.0.0 <4.17.21

  ⚠   Deprecated Packages
  request@2.88.2
    request has been deprecated...

  📦  Outdated Dependencies
  ┌──────────────────┬──────────┬──────────┬───────┐
  │ Package          │ Current  │ Latest   │ Type  │
  ├──────────────────┼──────────┼──────────┼───────┤
  │ next             │ 14.2.0   │ 15.1.0   │ major │
  └──────────────────┴──────────┴──────────┴───────┘
```

### JSON output

```bash
depguard --json
depguard --json > report.json
```

### Markdown output

```bash
depguard --markdown
depguard --markdown > DEPENDENCY_REPORT.md
```

---

## All CLI Flags

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |
| `--markdown` | Output as Markdown |
| `--fail-on-high` | Exit code 1 if critical/high vulnerabilities found |
| `--ignore <list>` | Comma-separated packages to skip e.g. `--ignore react,next` |
| `--workspace` | Scan all monorepo workspaces |
| `--deep` | Include transitive dependencies (`scan` command only) |
| `--production` | Only scan production deps (skip devDependencies) |
| `-v, --version` | Print version |
| `-h, --help` | Show help |

---

## CI / CD Integration

### GitHub Actions

```yaml
# .github/workflows/dep-health.yml
name: Dependency Health

on: [push, pull_request]

jobs:
  depguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npx @lbharath/depguard --fail-on-high
```

### GitLab CI

```yaml
dep-health:
  image: node:20
  script:
    - npm ci
    - npx @lbharath/depguard --fail-on-high
```

### JSON report as CI artifact

```bash
depguard --json > dep-report.json
```

---

## Supported Package Managers

| Package Manager | Outdated | Audit | Workspaces |
|-----------------|----------|-------|------------|
| npm             | ✅ | ✅ | ✅ |
| pnpm            | ✅ | ✅ | ✅ |
| yarn v1         | ✅ | ✅ | ✅ |
| yarn berry v2+  | partial | ✅ | ✅ |
| bun             | ✅ | via OSV | ✅ |
| deno            | — | via OSV | — |

---

## Data Sources

- **[npm registry](https://registry.npmjs.org)** — installed versions, deprecation status, publish history
- **[OSV.dev](https://osv.dev)** — open-source vulnerability database (Google), free, no API key required
- **npm/pnpm/yarn audit** — native package manager vulnerability reports

---

## How to Publish to npm (CDN distribution)

Publishing to npm makes DepGuard available on:
- **npm registry** → `npm install -g depguard`
- **unpkg CDN** → `https://unpkg.com/depguard/`
- **jsDelivr CDN** → `https://cdn.jsdelivr.net/npm/depguard/`
- **`npx depguard`** — zero-install usage for anyone

### Step-by-step publishing guide

#### 1. Create an npm account

Go to [https://www.npmjs.com](https://www.npmjs.com) and create a free account.

#### 2. Log in from your terminal

```bash
npm login
# Enter your username, password, and email
# Complete any 2FA if enabled
```

#### 3. Set your author info (optional but recommended)

Edit `package.json`:

```json
{
  "author": "Your Name <you@example.com> (https://yoursite.com)",
  "repository": {
    "type": "git",
    "url": "https://github.com/YOUR_USERNAME/depguard"
  },
  "homepage": "https://github.com/YOUR_USERNAME/depguard#readme",
  "bugs": {
    "url": "https://github.com/YOUR_USERNAME/depguard/issues"
  }
}
```

#### 4. Build the project

```bash
npm run build
```

This compiles TypeScript → `dist/index.js` with the shebang line prepended.

#### 5. Verify what will be published

```bash
npm pack --dry-run
```

You should see `dist/`, `README.md`, and `LICENSE` listed.

#### 6. Publish

```bash
npm publish
```

For scoped packages (e.g. `@yourname/depguard`):

```bash
npm publish --access public
```

#### 7. Your package is now live!

Anyone can install it:

```bash
# Global install
npm install -g @lbharath/depguard

# Zero-install
npx @lbharath/depguard

# Project dependency
npm install --save-dev @lbharath/depguard
```

CDN URLs (available automatically after publishing):

```
https://unpkg.com/@lbharath/depguard@latest/dist/index.js
https://cdn.jsdelivr.net/npm/@lbharath/depguard@latest/dist/index.js
```

#### 8. Publishing updates

```bash
# Bump the version (choose: patch | minor | major)
npm version patch   # 1.0.12 → 1.0.13
npm version minor   # 1.0.11 → 1.1.0
npm version major   # 1.0.11 → 2.0.0

# Then publish
npm publish
```

---

## Development

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/depguard
cd depguard

# Install dependencies
npm install

# Run in development mode (no build step needed)
npm run dev

# Build for production
npm run build

# Type-check without building
npm run typecheck
```

---

## Project Structure

```
depguard/
├── src/
│   ├── index.ts              # CLI entry point
│   ├── types/index.ts        # Shared TypeScript types
│   ├── cli/program.ts        # Commander.js setup
│   ├── detector/index.ts     # Package manager + monorepo detection
│   ├── scanner/              # Per-PM scanner engines
│   │   ├── index.ts
│   │   ├── npm.ts
│   │   ├── pnpm.ts
│   │   ├── yarn.ts
│   │   └── bun.ts
│   ├── normalizer/index.ts   # Raw output → DependencyInfo
│   ├── analyzers/            # Health enrichment
│   │   ├── index.ts
│   │   ├── vulnerability.ts  # OSV.dev API
│   │   ├── deprecation.ts    # npm registry deprecation
│   │   └── maintenance.ts    # npm registry publish dates
│   └── reporters/            # Output formatters
│       ├── index.ts
│       ├── terminal.ts
│       ├── json.ts
│       └── markdown.ts
├── dist/                     # Compiled output (git-ignored)
├── package.json
├── tsconfig.json
└── tsup.config.ts
```

---

## Output JSON Schema

```json
{
  "project": "my-app",
  "packageManager": "npm",
  "directory": "/path/to/project",
  "scanDate": "2024-01-15T10:30:00.000Z",
  "summary": {
    "total": 42,
    "outdated": 8,
    "vulnerable": 2,
    "deprecated": 1,
    "stale": 3,
    "critical": 1,
    "high": 1,
    "moderate": 0,
    "low": 0
  },
  "dependencies": [
    {
      "name": "lodash",
      "current": "4.17.15",
      "latest": "4.17.21",
      "wanted": "4.17.21",
      "severity": "critical",
      "deprecated": false,
      "stale": false,
      "archived": false,
      "riskLevel": "critical",
      "updateType": "patch",
      "isDev": false,
      "vulnerabilities": [
        {
          "id": "GHSA-...",
          "title": "Prototype Pollution",
          "severity": "critical",
          "affectedVersions": ">=0.0.0 <4.17.21",
          "url": "https://github.com/advisories/...",
          "source": "osv"
        }
      ]
    }
  ],
  "errors": []
}
```

---

## License

[MIT](./LICENSE) — free to use, modify, and distribute.
