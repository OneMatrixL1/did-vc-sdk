# Setting Up ethr-did Git Submodules

This guide walks you through setting up ethr-did and ethr-did-resolver as git submodules in the Dock SDK.

## Phase 1: Create Forks (Manual GitHub Steps)

### Step 1.1: Create ethr-did Fork
1. Go to https://github.com/uport-project/ethr-did
2. Click "Fork" button in top right
3. Select "OneMatrixL1" as the owner
4. Confirm fork creation
5. Copy the fork URL: `https://github.com/OneMatrixL1/ethr-did.git`

### Step 1.2: Create ethr-did-resolver Fork
1. Go to https://github.com/uport-project/ethr-did-resolver
2. Click "Fork" button in top right
3. Select "OneMatrixL1" as the owner
4. Confirm fork creation
5. Copy the fork URL: `https://github.com/OneMatrixL1/ethr-did-resolver.git`

### Step 1.3: Tag Base Versions in ethr-did Fork
```bash
# Clone the fork locally (temporary)
git clone https://github.com/OneMatrixL1/ethr-did.git /tmp/ethr-did-temp
cd /tmp/ethr-did-temp

# Find and checkout the v2.3.23 tag
git fetch origin "refs/tags/v2.3.23:refs/tags/v2.3.23"
git checkout v2.3.23

# Create a marker tag for reference
git tag base-upstream-2.3.23
git push origin base-upstream-2.3.23

# Clean up
cd /
rm -rf /tmp/ethr-did-temp
```

### Step 1.4: Tag Base Versions in ethr-did-resolver Fork
```bash
# Clone the fork locally (temporary)
git clone https://github.com/OneMatrixL1/ethr-did-resolver.git /tmp/ethr-did-resolver-temp
cd /tmp/ethr-did-resolver-temp

# Find and checkout the v10.1.10 tag
git fetch origin "refs/tags/v10.1.10:refs/tags/v10.1.10"
git checkout v10.1.10

# Create a marker tag for reference
git tag base-upstream-10.1.10
git push origin base-upstream-10.1.10

# Clean up
cd /
rm -rf /tmp/ethr-did-resolver-temp
```

## Phase 2: Add Submodules to Credential SDK

Run the following commands from the root of the SDK repository:

### Step 2.1: Add ethr-did Submodule
```bash
git submodule add https://github.com/OneMatrixL1/ethr-did.git packages/ethr-did
cd packages/ethr-did
git remote add upstream https://github.com/uport-project/ethr-did.git
cd ../../
```

### Step 2.2: Add ethr-did-resolver Submodule
```bash
git submodule add https://github.com/OneMatrixL1/ethr-did-resolver.git packages/ethr-did-resolver
cd packages/ethr-did-resolver
git remote add upstream https://github.com/uport-project/ethr-did-resolver.git
cd ../../
```

### Step 2.3: Verify Submodule Setup
```bash
# Check .gitmodules
cat .gitmodules

# Verify submodule remotes
cd packages/ethr-did
git remote -v
echo "---"
cd ../ethr-did-resolver
git remote -v
cd ../../
```

### Step 2.4: Commit Submodule Changes
```bash
git add .gitmodules packages/ethr-did packages/ethr-did-resolver
git commit -m "feat: add ethr-did and ethr-did-resolver as git submodules"
```

## Phase 3: Update Yarn Workspaces

> **Note**: This project uses Yarn v1.x, which requires `file:` paths for local dependencies. If you were to upgrade to Yarn 3+ (Berry), you could use the `workspace:*` protocol instead, but the current setup uses `file:../` paths for compatibility.

### Step 3.1: Update Root package.json
Edit `package.json` at the root and add the new packages to the workspaces array:

```json
{
  "workspaces": [
    "packages/credential-sdk",
    "packages/cheqd-blockchain-api",
    "packages/cheqd-blockchain-modules",
    "packages/ethr-did",
    "packages/ethr-did-resolver"
  ]
}
```

### Step 3.2: Update credential-sdk Dependencies
Edit `packages/credential-sdk/package.json` and update:

```json
{
  "dependencies": {
    "ethr-did": "file:../ethr-did",
    "ethr-did-resolver": "file:../ethr-did-resolver"
  }
}
```

### Step 3.3: Install and Verify
```bash
# Clean install
rm -rf node_modules yarn.lock
yarn install

# Verify workspaces
yarn workspaces list

# Verify credential-sdk can import ethr-did
cd packages/credential-sdk
node -e "const ethrDid = require('ethr-did'); console.log('✓ ethr-did imported successfully')" || echo "✗ Import failed"
cd ../../
```

## Common Operations

### Clone with Submodules
When cloning the repo, use:
```bash
git clone --recurse-submodules https://github.com/docknetwork/credential-sdk.git
```

Or if already cloned:
```bash
git submodule update --init --recursive
```

### Pull Latest Updates
```bash
# Pull main repo and submodules
git pull && git submodule update --recursive
```

### Pull Latest from Upstream
```bash
# Update ethr-did from upstream
cd packages/ethr-did
git pull upstream main

# Update ethr-did-resolver from upstream
cd ../ethr-did-resolver
git pull upstream main
cd ../../
```

### Create Feature Branch in Submodule
```bash
cd packages/ethr-did
git checkout -b feature/custom-key-types
# ... make changes
git commit -am "feat: add custom key type support"
git push origin feature/custom-key-types
cd ../../
```

## Phase 4: CI/CD Integration

When you push changes to GitHub, ensure your repository's CI/CD configuration includes submodule handling.

### GitHub Actions Configuration
If using GitHub Actions for CI/CD, add the following to your checkout steps in workflow files:

```yaml
- uses: actions/checkout@v4
  with:
    submodules: true
    fetch-depth: 0
```

The `fetch-depth: 0` ensures full history is available for builds that may need it.

### Repository Settings (GitHub Web UI)
1. Go to your repository Settings
2. Navigate to "Code and automation" > "Actions"
3. Ensure you have "Submodules" support enabled in your CI/CD

## Troubleshooting

### Submodule at wrong commit
```bash
git submodule update --init --recursive
```

### Upstream remote not found
```bash
cd packages/ethr-did
git remote add upstream https://github.com/uport-project/ethr-did.git
```

### Need to switch submodule branch
```bash
cd packages/ethr-did
git checkout dock/main  # or whatever branch you want
cd ../../
git add packages/ethr-did
git commit -m "chore: update ethr-did to dock/main branch"
```
