# Standard Submodule Workflow Guide

This document outlines the standard process for managing, building, and updating submodules (`ethr-did`, `ethr-did-resolver`) within the `did-vc-sdk` monorepo.

## 1. Initializing Submodules

When cloning the repo for the first time or when you need to "reset" the submodule state to match the commits tracked by the main repository:

```bash
# De-initialize to clear the old state (if a full reset is needed)
git submodule deinit -f .

# Initialize and update to the commits stored in the main repo
git submodule update --init --recursive
```

## 2. Updating to a Specific Branch (e.g., `feat/dual-did`)

To update submodules to a specific branch and pull the latest changes:

```bash
# Repeat for each submodule
cd packages/ethr-did-resolver
git fetch origin
git checkout feat/dual-did
git pull origin feat/dual-did

cd ../ethr-did
git fetch origin
git checkout feat/dual-did
git pull origin feat/dual-did
```

## 3. Build Process (Dependency Order)

**CRITICAL:** `ethr-did` depends on `ethr-did-resolver`. If you attempt to build `ethr-did` before building the `resolver`, you will encounter the error: `Cannot find module 'ethr-did-resolver'`.

### Step A: Build Resolver First
```bash
cd packages/ethr-did-resolver
yarn install
yarn build
```
This generates the `lib/` folder containing necessary type definitions (`.d.ts`) and compiled logic.

### Step B: Build Ethr-DID Second
```bash
cd ../ethr-did
yarn install
yarn build
```

## 4. Applying Changes to the Main SDK

After submodules are built, update the main repository's dependencies to recognize these changes:

```bash
# Return to the did-vc-sdk root directory
cd ../..
yarn install
```

## 5. Verification and Commit

1. **Run Tests:**
   ```bash
   yarn jest tests/did-owner-history.test.js
   ```

2. **Commit Submodule Changes:**
   When you change the commit inside a submodule, the main repo will detect it as a change in the submodule directory.
   ```bash
   git add packages/ethr-did packages/ethr-did-resolver
   git commit -m "chore: update submodules to latest feat/dual-did"
   ```

---

### Quick Summary Commands:
```bash
# Build everything in the correct order
(cd packages/ethr-did-resolver && yarn build) && \
(cd packages/ethr-did && yarn build) && \
yarn install
```
