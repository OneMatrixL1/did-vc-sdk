# Change: Add ethr-did and ethr-did-resolver as Git Submodules

## Why

The Dock SDK requires enhanced control over ethr-did and ethr-did-resolver to support:
- Additional cryptographic key types for DID management
- Modified DID resolution logic for better integration with Cheqd and custom resolvers
- Extended delegation and verification methods aligned with Dock's credential architecture
- Regular synchronization with upstream while maintaining custom modifications

Using git submodules enables independent version control, easier upstream syncing, and full integration with the monorepo build system via Yarn workspaces.

## What Changes

- Fork ethr-did and ethr-did-resolver repositories (maintaining origin remotes for upstream sync)
- Add git submodules at `packages/ethr-did/` and `packages/ethr-did-resolver/`
- Configure Yarn workspaces to include submodule packages alongside existing packages
- Update credential-sdk dependencies to reference local workspace packages
- Establish contribution workflow for upstream syncing and custom change management
- Document integration patterns in project.md and architecture guidelines

### Breaking Changes
- None for credential-sdk consumers; internal dependency upgrade only

## Impact

- **Affected specs**: ethr-did-integration (new)
- **Affected code**:
  - package.json (root) - Yarn workspace configuration
  - packages/credential-sdk/package.json - ethr-did/ethr-did-resolver dependencies
  - turbo.json - Build task dependencies if needed
  - .gitmodules - New submodule declarations
- **Build system**: Turbo build orchestration may require task reordering
- **CI/CD**: GitHub workflows need to fetch submodules during checkout
