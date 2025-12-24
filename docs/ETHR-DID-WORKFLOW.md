# ethr-did Git Submodule Workflow

This document describes how to work with the ethr-did and ethr-did-resolver packages as git submodules in the Dock SDK.

## Quick Start

### First Time Setup
```bash
# Clone the SDK with all submodules
git clone --recurse-submodules https://github.com/docknetwork/sdk.git
cd sdk

# If you already cloned without submodules, initialize them
git submodule update --init --recursive

# Install dependencies and build
yarn install
```

### Daily Workflow

```bash
# Pull latest changes from main branch and update submodules
git pull && git submodule update --recursive

# Make sure builds are up to date
cd packages/ethr-did && yarn build && cd ../..
cd packages/ethr-did-resolver && yarn build && cd ../..

# Run tests
cd packages/credential-sdk && yarn test
```

## Working with Submodules

### Viewing Submodule Status
```bash
# Show which commits submodules are pointing to
git submodule foreach 'echo $name && git log -1 --oneline'

# Show submodule remotes
cd packages/ethr-did
git remote -v
cd ../../
```

### Making Changes in a Submodule

#### Create a feature branch
```bash
cd packages/ethr-did
git checkout -b feature/my-feature
# Make your changes...
git add src/...
git commit -m "feat: add my feature"
git push origin feature/my-feature
cd ../../
```

#### Submit upstream PR (optional)
If your changes benefit the uport-project community:

```bash
cd packages/ethr-did
# Create a PR against https://github.com/uport-project/ethr-did
# Include reference to the feature branch
cd ../../
```

#### Merge into dock/main for integration
After review and approval in your Dock fork:

```bash
cd packages/ethr-did
git checkout dock/main
git merge feature/my-feature
git push origin dock/main
cd ../../
```

#### Update main repo to track new submodule commit
```bash
# In the root directory
git add packages/ethr-did
git commit -m "chore: update ethr-did to dock/main with new feature"
git push
```

## Syncing with Upstream

### Pull Latest Upstream Changes
```bash
cd packages/ethr-did

# Fetch latest from uport-project
git fetch upstream

# Merge upstream into your branch
git merge upstream/main

# Resolve any conflicts
# ...

# Push updated branch
git push origin dock/main
cd ../../

# Update the main repo
git add packages/ethr-did
git commit -m "chore: sync ethr-did with upstream"
```

### Check for Breaking Changes
Before syncing with upstream:

```bash
cd packages/ethr-did
git log upstream/main --oneline -20
# Review commits to understand what's changing

# Check release notes
# Visit https://github.com/uport-project/ethr-did/releases
cd ../../
```

## Building the Submodules

### Build a single submodule
```bash
cd packages/ethr-did
yarn build
cd ../../
```

### Build both submodules
```bash
cd packages/ethr-did && yarn build && cd ../..
cd packages/ethr-did-resolver && yarn build && cd ../..
```

### Build all packages (including credential-sdk)
```bash
yarn build
```

## Testing

### Test credential-sdk (includes ethr-did)
```bash
cd packages/credential-sdk
yarn test
cd ../../
```

### Test with integration tests
```bash
cd packages/credential-sdk
yarn test --testPathPattern=integration
cd ../../
```

### Test submodule in isolation (if needed)
```bash
cd packages/ethr-did
yarn test
cd ../../
```

## Troubleshooting

### Submodule is at wrong commit
Reset to expected commit:
```bash
git submodule update --init --recursive
```

### Changes in submodule not reflected in credential-sdk
Rebuild the submodule:
```bash
cd packages/ethr-did
yarn build
cd ../../
rm -rf node_modules && yarn install
```

### Git complains about uncommitted changes in submodule
```bash
# Check submodule status
git status

# If you've made changes you want to keep
cd packages/ethr-did
git add .
git commit -m "my changes"
cd ../../
git add packages/ethr-did
git commit -m "chore: update ethr-did ref"

# If you want to discard changes
git submodule foreach 'git reset --hard'
```

### Merge conflict in submodule
```bash
cd packages/ethr-did
# Resolve conflicts in source files
git add resolved-files
git commit -m "resolve: merge conflict in ..."
cd ../../
git add packages/ethr-did
git commit -m "chore: resolve ethr-did merge conflict"
```

## Advanced: Maintaining Custom Branches

### Create a dock-specific branch
```bash
cd packages/ethr-did
git checkout -b dock/feature-name upstream/main
# Make Dock-specific changes
git commit -am "dock: custom feature"
git push origin dock/feature-name
cd ../../
```

### Track dock/main as primary branch
```bash
cd packages/ethr-did
git checkout dock/main
git config branch.dock/main.merge refs/heads/main # track upstream/main
cd ../../
```

## CI/CD Integration

The GitHub Actions workflows automatically:
1. Fetch submodules when checking out code
2. Build submodules before testing credential-sdk
3. Run credential-sdk tests with local submodule versions

If you push changes to a submodule fork:
1. Update the main repo to point to the new commit
2. Push to main
3. CI/CD will automatically test with the new submodule version

## Support & Questions

For issues related to:
- **ethr-did changes**: Check with the Dock team in #engineering
- **Upstream ethr-did**: Visit https://github.com/uport-project/ethr-did/issues
- **Credential-sdk integration**: Check SETUP_SUBMODULES.md or ask in #sdk-dev
