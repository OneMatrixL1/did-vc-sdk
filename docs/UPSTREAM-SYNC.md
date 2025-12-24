# Upstream Synchronization Process

This document describes how to keep the Dock SDK's ethr-did and ethr-did-resolver forks synchronized with the upstream repositories.

## Sync Schedule

- **Frequency**: Monthly (first Monday of each month)
- **Responsible**: SDK maintenance team
- **Time**: As part of regular maintenance cycle

## Pre-Sync Checklist

- [ ] No active critical issues in credential-sdk related to ethr-did
- [ ] All current credential-sdk tests passing
- [ ] Review upstream changelog for breaking changes
- [ ] Notify team of planned sync

## Sync Process

### Step 1: Review Upstream Changes

```bash
cd packages/ethr-did

# Fetch latest from upstream
git fetch upstream

# View new commits since last sync
git log --oneline origin/dock/main..upstream/main | head -20

# View detailed changes
git log --stat origin/dock/main..upstream/main

# Check releases and changelogs
# https://github.com/uport-project/ethr-did/releases
```

### Step 2: Identify Breaking Changes

Look for:
- Major version bumps in dependencies
- Removed or renamed exports
- Changed function signatures
- Security fixes (may require code changes)

### Step 3: Create Sync Branch

```bash
cd packages/ethr-did

# Create a new branch for sync
git checkout -b sync/upstream-$(date +%Y-%m-%d)

# Or update existing dock/main if preferred
git checkout dock/main
```

### Step 4: Merge Upstream

```bash
cd packages/ethr-did

# Merge upstream into current branch
git merge upstream/main --no-ff -m "chore: sync upstream ethr-did"

# Resolve any conflicts
# - Most common: version number bumps
# - Handle each conflict carefully
# - Test after resolving conflicts
```

### Step 5: Test Sync Result

```bash
cd packages/ethr-did
yarn install
yarn build

# Check build succeeds
if [ $? -ne 0 ]; then
  echo "Build failed! Review merge conflicts."
  git merge --abort
  exit 1
fi

cd ../../
```

### Step 6: Test Integration with credential-sdk

```bash
cd packages/credential-sdk
yarn test

# If tests fail:
# 1. Review test output
# 2. Check if changes are in ethr-did or credential-sdk
# 3. Decide: update credential-sdk or revert sync

cd ../../
```

### Step 7: Approve or Revert

#### If sync successful:
```bash
cd packages/ethr-did
git push origin sync/upstream-$(date +%Y-%m-%d)
# Create PR and request review
cd ../../
```

#### If sync has issues:
```bash
cd packages/ethr-did
git merge --abort  # or git reset --hard before merge
cd ../../
```

### Step 8: Merge to dock/main

After PR approval:

```bash
cd packages/ethr-did
git checkout dock/main
git merge --ff-only sync/upstream-$(date +%Y-%m-%d)
git push origin dock/main
cd ../../
```

### Step 9: Update Main Repository

```bash
# Commit submodule pointer update
git add packages/ethr-did
git commit -m "chore: update ethr-did to latest upstream

- Synced with uport-project/ethr-did $(git -C packages/ethr-did log -1 --oneline upstream/main)
- Breaking changes: [list any if applicable]
- Testing: [note test results]
"

# Or for ethr-did-resolver
git add packages/ethr-did-resolver
git commit -m "chore: update ethr-did-resolver to latest upstream"

git push origin master
```

## Handling Conflicts

### Common Conflict: Version Number
```bash
# In package.json
# Keep our version number if we haven't patched it ourselves
# Update if we're just tracking upstream

<<<<<<< HEAD
"version": "3.0.38"
=======
"version": "3.0.39"
>>>>>>> upstream/main

# Usually accept upstream version
git checkout --theirs package.json
git add package.json
```

### Common Conflict: Build Configuration
Review both versions of the conflicted file:
```bash
# See their changes
git show :2:filename

# See our changes
git show :3:filename

# Merge intelligently - may need both changes
```

### Common Conflict: Documentation
Usually safe to keep our documentation:
```bash
git checkout --ours README.md
git add README.md
```

## Post-Sync Verification

After sync merges to dock/main:

1. **CI/CD Check**: Ensure all workflows pass
   ```bash
   # Wait for GitHub Actions to complete
   # https://github.com/docknetwork/sdk/actions
   ```

2. **Integration Test**: Test credential-sdk thoroughly
   ```bash
   cd packages/credential-sdk
   yarn test --testPathPattern=ethr-did
   ```

3. **Release Notes**: Document any breaking changes
   ```bash
   # Update CHANGELOG.md
   # Note any credential-sdk changes needed due to upstream
   ```

## Rollback Procedure

If sync causes major issues:

```bash
# Identify the problematic commit
git log --oneline -10 packages/ethr-did

# Revert the sync commit
git revert <sync-commit-hash>

# Or reset to before sync
git reset --hard <commit-before-sync>

# Force push if necessary (use with caution!)
git push origin master --force-with-lease
```

## Monthly Sync Checklist

- [ ] Pull latest from `upstream/main` in both submodules
- [ ] Review commit logs for breaking changes
- [ ] Create sync branches
- [ ] Merge upstream with conflict resolution
- [ ] Build both submodules successfully
- [ ] Run credential-sdk full test suite
- [ ] Merge to dock/main after review
- [ ] Update main repository pointer commits
- [ ] Verify CI/CD passes
- [ ] Document any breaking changes
- [ ] Notify team of sync completion

## Emergency Sync (Security Patches)

If upstream releases security patches:

```bash
# Expedited process
cd packages/ethr-did
git fetch upstream
git merge upstream/main --ff-only  # Fast-forward only

# Quick test
yarn build
cd ../../

# Fast-track to master
git add packages/ethr-did
git commit -m "security: apply ethr-did upstream security patch"
git push origin master
```

## Future Considerations

- **Automation**: Consider GitHub Actions for automated upstream pull
- **Branching**: May migrate to `dk-did/main` branch naming for clarity
- **Release Sync**: Consider syncing on upstream major releases
- **Custom Patches**: Document any Dock-specific patches that diverge from upstream

## Resources

- ethr-did repository: https://github.com/uport-project/ethr-did
- ethr-did-resolver repository: https://github.com/uport-project/ethr-did-resolver
- Dock SDK main: https://github.com/docknetwork/sdk
- Git submodule guide: https://git-scm.com/book/en/v2/Git-Tools-Submodules
