# Implementation Tasks: Add ethr-did Git Submodules

## 1. Preparation & Fork Setup
- [ ] 1.1 Create Dock fork of ethr-did repository (github.com/docknetwork/ethr-did)
- [ ] 1.2 Create Dock fork of ethr-did-resolver repository (github.com/docknetwork/ethr-did-resolver)
- [ ] 1.3 Tag base versions in forks:
  - [ ] 1.3.1 Tag ethr-did at v2.3.23 as `base-upstream-2.3.23`
  - [ ] 1.3.2 Tag ethr-did-resolver at v10.1.10 as `base-upstream-10.1.10`
- [ ] 1.4 Configure upstream remotes in both forks
  - [ ] 1.4.1 Add upstream remote to ethr-did fork → uport-project/ethr-did
  - [ ] 1.4.2 Add upstream remote to ethr-did-resolver fork → uport-project/ethr-did-resolver

## 2. Git Submodule Integration
- [ ] 2.1 Add ethr-did submodule to main repo
  - [ ] 2.1.1 Execute: `git submodule add <dock-ethr-did-fork-url> packages/ethr-did`
  - [ ] 2.1.2 Verify .gitmodules entry for ethr-did
  - [ ] 2.1.3 Run `git submodule update --init` to initialize
- [ ] 2.2 Add ethr-did-resolver submodule to main repo
  - [ ] 2.2.1 Execute: `git submodule add <dock-ethr-did-resolver-fork-url> packages/ethr-did-resolver`
  - [ ] 2.2.2 Verify .gitmodules entry for ethr-did-resolver
  - [ ] 2.2.3 Run `git submodule update --init` to initialize
- [ ] 2.3 Configure upstream remotes in submodules
  - [ ] 2.3.1 `cd packages/ethr-did && git remote add upstream <uport-project-url>`
  - [ ] 2.3.2 `cd packages/ethr-did-resolver && git remote add upstream <uport-project-url>`
- [ ] 2.4 Commit submodule changes
  - [ ] 2.4.1 Add .gitmodules and submodule references
  - [ ] 2.4.2 Create commit: "feat: add ethr-did and ethr-did-resolver as git submodules"

## 3. Yarn Workspace Configuration
- [ ] 3.1 Update root package.json
  - [ ] 3.1.1 Add `packages/ethr-did` to workspaces array
  - [ ] 3.1.2 Add `packages/ethr-did-resolver` to workspaces array
  - [ ] 3.1.3 Verify workspace array order (recommended: existing packages + new submodules)
- [ ] 3.2 Verify workspace configuration
  - [ ] 3.2.1 Run `yarn workspaces list` to confirm all packages appear
  - [ ] 3.2.2 Check that credential-sdk is listed as dependent on ethr-did and ethr-did-resolver

## 4. Credential-SDK Dependency Updates
- [ ] 4.1 Update packages/credential-sdk/package.json
  - [ ] 4.1.1 Replace `"ethr-did": "^2.3.23"` with `"ethr-did": "workspace:*"`
  - [ ] 4.1.2 Replace `"ethr-did-resolver": "^10.1.10"` with `"ethr-did-resolver": "workspace:*"`
- [ ] 4.2 Test dependency resolution
  - [ ] 4.2.1 Run `yarn install` from root directory
  - [ ] 4.2.2 Verify no warnings about workspace:* protocol
  - [ ] 4.2.3 Check that credential-sdk can import ethr-did modules

## 5. Build System Integration
- [ ] 5.1 Verify Turbo recognizes workspace dependencies
  - [ ] 5.1.1 Run `yarn build` and confirm ethr-did and ethr-did-resolver build before credential-sdk
  - [ ] 5.1.2 Check turbo.json for any required task dependencies (likely none needed)
  - [ ] 5.1.3 Test clean build: `rm -rf dist && yarn build`
- [ ] 5.2 Test local package linking
  - [ ] 5.2.1 Modify a simple file in packages/ethr-did
  - [ ] 5.2.2 Run credential-sdk build and verify change is picked up

## 6. CI/CD Workflow Updates
- [ ] 6.1 Update GitHub Actions workflows to fetch submodules
  - [ ] 6.1.1 Edit `.github/workflows/lint.yml`
    - [ ] Add `submodules: true` to checkout step
  - [ ] 6.1.2 Edit `.github/workflows/credential-sdk-tests.yml`
    - [ ] Add `submodules: true` to checkout step
  - [ ] 6.1.3 Edit `.github/workflows/cheqd-api-tests.yml`
    - [ ] Add `submodules: true` to checkout step
  - [ ] 6.1.4 Edit `.github/workflows/cheqd-modules-tests.yml`
    - [ ] Add `submodules: true` to checkout step
  - [ ] 6.1.5 Edit `.github/workflows/docs.yml`
    - [ ] Add `submodules: true` to checkout step
  - [ ] 6.1.6 Edit `.github/workflows/npm-publish.yml`
    - [ ] Add `submodules: true` to checkout step
- [ ] 6.2 Test workflow changes locally (if possible)
  - [ ] 6.2.1 Simulate fresh checkout with submodules
  - [ ] 6.2.2 Verify CI environment has all source files

## 7. Testing & Validation
- [ ] 7.1 Run credential-sdk test suite
  - [ ] 7.1.1 Execute: `yarn test` in credential-sdk package
  - [ ] 7.1.2 Verify all ethr-did related tests pass
  - [ ] 7.1.3 Check for any import or resolution errors
- [ ] 7.2 Test DID resolution with local ethr-did
  - [ ] 7.2.1 Create integration test for ethr DID resolution
  - [ ] 7.2.2 Verify resolution works with both Cheqd and local implementations
  - [ ] 7.2.3 Test key type handling for custom schemes
- [ ] 7.3 Verify build artifacts
  - [ ] 7.3.1 Check dist/ directories are properly generated
  - [ ] 7.3.2 Verify dist/esm and dist/cjs contain ethr-did dependencies

## 8. Documentation & Contributor Guidelines
- [ ] 8.1 Document git submodule workflow
  - [ ] 8.1.1 Create SUBMODULE_WORKFLOW.md with common operations
    - [ ] Clone with submodules: `git clone --recurse-submodules`
    - [ ] Update submodules: `git submodule update --init --recursive`
    - [ ] Pull latest: `git pull && git submodule update`
- [ ] 8.2 Document upstream synchronization process
  - [ ] 8.2.1 Add upstream-sync.md covering:
    - [ ] Pulling upstream changes
    - [ ] Handling merge conflicts
    - [ ] Testing after sync
    - [ ] Creating change proposals for new upstream features
- [ ] 8.3 Update openspec/project.md
  - [ ] 8.3.1 Add note about ethr-did/ethr-did-resolver as submodules in architecture section
  - [ ] 8.3.2 Document workspace protocol in project conventions
  - [ ] 8.3.3 Add upstream sync schedule (e.g., monthly reviews)
- [ ] 8.4 Update main README.md
  - [ ] 8.4.1 Add submodule initialization to setup instructions
  - [ ] 8.4.2 Reference SUBMODULE_WORKFLOW.md for contributors

## 9. Upstream Sync Preparation
- [ ] 9.1 Create upstream sync workflow
  - [ ] 9.1.1 Document monthly sync schedule
  - [ ] 9.1.2 Create checklist for sync reviews
  - [ ] 9.1.3 Identify contact points for upstream PRs
- [ ] 9.2 Test upstream sync process
  - [ ] 9.2.1 Pull latest from upstream/main in test environment
  - [ ] 9.2.2 Verify no conflicts with Dock customizations
  - [ ] 9.2.3 Document any breaking changes found

## 10. Final Verification & Merge
- [ ] 10.1 Run full test suite
  - [ ] 10.1.1 Execute: `yarn test`
  - [ ] 10.1.2 Execute: `yarn lint`
  - [ ] 10.1.3 Execute: `yarn build`
- [ ] 10.2 Verify all workflows pass
  - [ ] 10.2.1 Push changes and verify GitHub Actions pass
  - [ ] 10.2.2 Check all package tests pass
- [ ] 10.3 Final documentation review
  - [ ] 10.3.1 Review all new documentation for clarity
  - [ ] 10.3.2 Verify links and references are correct
- [ ] 10.4 Merge to main
  - [ ] 10.4.1 Resolve any final issues
  - [ ] 10.4.2 Merge pull request
  - [ ] 10.4.3 Verify main branch is stable

## 11. Post-Merge Tasks
- [ ] 11.1 Archive this change proposal
  - [ ] 11.1.1 Run `openspec archive add-ethr-did-submodules --yes`
- [ ] 11.2 Create capability spec for ethr-did-integration
  - [ ] 11.2.1 Move specs/ethr-did-integration/spec.md to openspec/specs/
  - [ ] 11.2.2 Create architecture reference documentation
- [ ] 11.3 Schedule first upstream sync
  - [ ] 11.3.1 Set calendar reminder for monthly sync
  - [ ] 11.3.2 Notify team of new process
