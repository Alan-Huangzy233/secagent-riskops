# SecAgent RiskOps v0.1.8 macOS Update

## Apply

```bash
cd ~/Downloads
unzip secagent-riskops-v018-update.zip

cd ~/secagent/secagent-riskops
git status
git pull --rebase origin main
rsync -av ~/Downloads/secagent-riskops-v018-update/ ./

python3 scripts/apply_v018_update.py
bash scripts/check_public_repo.sh
```

Resolve every `HIGH` result and manually review every `MEDIUM` result before committing.

## Protect Future Commit Metadata

Use the GitHub-provided no-reply email shown in GitHub Settings > Emails:

```bash
git config user.name "YOUR_PUBLIC_COMMIT_NAME"
git config user.email "YOUR_GITHUB_NOREPLY_EMAIL"
git config user.email
```

This changes future commits only.

## Commit and Push

```bash
git status
git add .
git commit -m "Add curated knowledge intake and public repo audit"
git pull --rebase origin main
git push origin main
```

## Create Milestone and Issues

```bash
bash scripts/create_v018_github_items.sh Alan-Huangzy233/secagent-riskops
```

Do not run the creation script twice without checking whether the items already exist.

## Inspect Existing Commit Metadata

```bash
git log --all --format='%h %an <%ae>'
```

Machine-local or personal email addresses already present in pushed history remain visible until history is rewritten.
