## ADDED Requirements

### Requirement: Git Submodule Integration for ethr-did
The system SHALL provide ethr-did as a git submodule at `packages/ethr-did/`, with source code and build artifacts managed locally while maintaining upstream synchronization capability.

#### Scenario: Initialize submodule with Dock fork
- **WHEN** a developer clones the credential-sdk repository
- **THEN** running `git submodule update --init --recursive` SHALL fetch ethr-did from the Dock fork

#### Scenario: Submodule contains proper remotes
- **WHEN** navigating to packages/ethr-did/
- **THEN** `git remote -v` SHALL show both `origin` (Dock fork) and `upstream` (uport-project original)

#### Scenario: Submodule is part of Yarn workspace
- **WHEN** running `yarn install` in the root directory
- **THEN** the ethr-did package SHALL be available to credential-sdk as `workspace:*` dependency

---

### Requirement: Git Submodule Integration for ethr-did-resolver
The system SHALL provide ethr-did-resolver as a git submodule at `packages/ethr-did-resolver/`, following the same structure and integration pattern as ethr-did.

#### Scenario: Initialize resolver submodule
- **WHEN** a developer clones the credential-sdk repository
- **THEN** running `git submodule update --init --recursive` SHALL fetch ethr-did-resolver from the Dock fork

#### Scenario: Resolver submodule workspace integration
- **WHEN** running `yarn install` in the root directory
- **THEN** the ethr-did-resolver package SHALL be available to credential-sdk as `workspace:*` dependency

---

### Requirement: Local Package Resolution via File Paths
The system SHALL configure credential-sdk to reference ethr-did and ethr-did-resolver submodules using file:// paths for local development (Yarn v1 compatible approach).

#### Scenario: File path dependencies configured
- **WHEN** inspecting package.json at credential-sdk package root
- **THEN** the dependencies section SHALL contain file:// paths:
  - `"ethr-did": "file:../ethr-did"`
  - `"ethr-did-resolver": "file:../ethr-did-resolver"`

#### Scenario: Local package symlinks created
- **WHEN** running `yarn install` from the repository root
- **THEN** Yarn SHALL create symlinks in node_modules:
  - `node_modules/ethr-did` → `packages/ethr-did`
  - `node_modules/ethr-did-resolver` → `packages/ethr-did-resolver`

#### Scenario: File path resolution works in development
- **WHEN** credential-sdk is built or tested
- **THEN** the build system SHALL use the local submodule versions via symlinks

---

### Requirement: Build System Uses Local Submodules
The system SHALL ensure the build process uses local submodule versions instead of npm registry versions.

#### Scenario: Build picks up local changes
- **WHEN** running `yarn build` for credential-sdk
- **THEN** the build process SHALL use the local submodule versions via symlinked paths

#### Scenario: Changes to submodules trigger rebuilds
- **WHEN** modifying source files in packages/ethr-did or packages/ethr-did-resolver
- **THEN** credential-sdk's build process SHALL detect changes and rebuild automatically

---

### Requirement: Git Submodule Configuration File
The system SHALL declare git submodules in .gitmodules with proper fork URLs and relative paths.

#### Scenario: .gitmodules contains ethr-did entry
- **WHEN** reading .gitmodules from the repository root
- **THEN** an entry for `[submodule "packages/ethr-did"]` SHALL exist with:
  - `path = packages/ethr-did`
  - `url = <Dock's ethr-did fork URL>`

#### Scenario: .gitmodules contains ethr-did-resolver entry
- **WHEN** reading .gitmodules from the repository root
- **THEN** an entry for `[submodule "packages/ethr-did-resolver"]` SHALL exist with:
  - `path = packages/ethr-did-resolver`
  - `url = <Dock's ethr-did-resolver fork URL>`

---

### Requirement: CI/CD Submodule Checkout
The system SHALL configure GitHub Actions workflows to fetch git submodules during CI/CD pipeline execution.

#### Scenario: Workflow fetches submodules before build
- **WHEN** a CI/CD workflow (lint.yml, credential-sdk-tests.yml, etc.) runs
- **THEN** the checkout action SHALL include:
  ```yaml
  with:
    submodules: true
    fetch-depth: 0
  ```

#### Scenario: Submodules available in build environment
- **WHEN** running tests or build steps in CI
- **THEN** packages/ethr-did and packages/ethr-did-resolver directories SHALL contain source code

---

### Requirement: Upstream Synchronization Capability
The system SHALL maintain upstream remotes in submodules to enable regular synchronization with original ethr-did and ethr-did-resolver repositories.

#### Scenario: Upstream remote configured in ethr-did
- **WHEN** a developer navigates to packages/ethr-did and runs `git remote -v`
- **THEN** an `upstream` remote SHALL point to the original uport-project/ethr-did repository

#### Scenario: Upstream sync workflow available
- **WHEN** a developer wants to pull latest upstream changes
- **THEN** running `git pull upstream <branch>` in packages/ethr-did/ SHALL fetch and merge upstream updates

#### Scenario: Custom changes remain after sync
- **WHEN** performing an upstream sync (git pull upstream)
- **THEN** Dock-specific modifications SHALL either merge cleanly or flag conflicts for manual resolution

---

### Requirement: Extended Key Type Support in ethr-did
The system SHALL support additional cryptographic key types in ethr-did beyond standard secp256k1, enabling integration with Dock's extended key schemes.

#### Scenario: Custom key type can be instantiated
- **WHEN** credential-sdk imports ethr-did and attempts to create a DID with a custom key type
- **THEN** the key type SHALL be recognized and processed without falling back to secp256k1 defaults

#### Scenario: Custom key type verification
- **WHEN** verifying a credential signed with a custom key type DID
- **THEN** the verification process SHALL use the extended key handling provided by the modified ethr-did

---

### Requirement: Modified DID Resolution Logic
The system SHALL allow modifications to DID resolution logic in ethr-did-resolver to support Dock-specific resolution patterns and Cheqd integration.

#### Scenario: Custom resolution method available
- **WHEN** credential-sdk uses ethr-did-resolver to resolve a DID
- **THEN** the resolver SHALL apply any Dock-specific resolution enhancements or fallback patterns

#### Scenario: Cheqd fallback in resolution
- **WHEN** an ethr DID resolution fails or requires additional context
- **THEN** the resolver MAY fallback to Cheqd resolution logic as configured

---

### Requirement: Extended Delegation and Verification Methods
The system SHALL extend ethr-did's delegation and verification capabilities to support credential-sdk's signing and delegation workflows.

#### Scenario: Custom delegation method available
- **WHEN** credential-sdk attempts to create a delegation using ethr-did
- **THEN** extended delegation methods SHALL be available beyond standard Ethereum message signing

#### Scenario: Verification with extended methods
- **WHEN** verifying a credential that used a Dock-extended verification method
- **THEN** the verification process SHALL correctly validate the signature using the extended method
