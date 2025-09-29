# Publishing to npm

This document describes how to set up npm publishing for the wasm-crypto package.

## Prerequisites

1. **npm account**: You need an npm account to publish packages
2. **npm token**: Generate an npm access token with publish permissions
3. **GitHub secrets**: Configure the NPM_TOKEN secret in the repository settings

## Setting up npm token

1. Visit [npmjs.com](https://www.npmjs.com) and log in to your account
2. Go to Access Tokens in your account settings
3. Generate a new token with "Automation" or "Publish" permissions
4. Copy the token (it starts with `npm_`)

## Configuring GitHub secrets

1. Go to your GitHub repository
2. Navigate to Settings > Secrets and variables > Actions
3. Click "New repository secret"
4. Name: `NPM_TOKEN`
5. Value: Paste your npm token
6. Click "Add secret"

## Publishing

### Automatic publishing on releases

1. Create a new release on GitHub
2. The `publish-npm.yml` workflow will automatically trigger
3. The package will be built and published to npm

### Manual publishing

1. Go to the Actions tab in your GitHub repository
2. Select the "Publish to npm" workflow
3. Click "Run workflow"
4. Optionally specify a version number
5. Click "Run workflow"

## Package structure

The published package includes:

- `wasm_crypto.js` - JavaScript bindings
- `wasm_crypto_bg.wasm` - WebAssembly binary
- `wasm_crypto.d.ts` - TypeScript definitions
- `package.json` - Package metadata

## Versioning

- The version is taken from `Cargo.toml`
- You can override the version when manually triggering the workflow
- Follow semantic versioning (semver) guidelines

## Testing

The repository includes a test workflow (`test-build.yml`) that:

- Builds the Rust code for WebAssembly
- Runs wasm-pack to generate the npm package
- Verifies the package structure

This runs on every push and pull request to ensure the build works before publishing.