# Auto-Merge Dependabot PRs GitHub App

This repo contains the code for https://github.com/apps/auto-merge-dependabot-prs.

See that page for an explanation of why a GitHub App is better than using a Personal Access Token for setting up auto-merge of dependabot PRs.

## Installing this GitHub App in your repo

Again, see https://github.com/apps/auto-merge-dependabot-prs (or the [source](./docs/DESCRIPTION.md))for instructions.

## Deploying

Here is a sketch of how to deploy this code yourself:

### To AWS

```sh
# Install Rust (see https://www.rust-lang.org/tools/install)

# Put cargo-lambda in PATH
python3 -m venv ~/opt/venv
source ~/opt/venv/bin/activate
pip3 install cargo-lambda

# Deploy to AWS
export AWS_PROFILE=auto-merge-preview
sam build --beta-features && sam deploy --parameter-overrides "GitHubAppID=1234567 DeployedCommit=$(git rev-parse HEAD)"
openssl rand 32 | base64 --wrap=0 | aws secretsmanager create-secret --name webhook-secret --secret-string file:///dev/stdin
```

### Register new GitHub App

1. Go to https://github.com/settings/apps and click _New GitHub App_. Fill in like this:

*GitHub App name*: whatever
*Homepage URL*: whatever
*Webhook Active*: Yes
*Webhook URL*: Your Lambda URL (https://abcd1234.execute-api.eu-west-1.amazonaws.com/Prod/webhook)
*Secret*: Output of `aws secretsmanager get-secret-value --secret-id webhook-secret | jq --raw-output .SecretString`
*Repository permissions*: Contents: Read and write, Pull Requests: Read and write
*Subscribe to events*: Pull request
*Where can this GitHub App be installed?* Any account

2. Click "Crate GitHub App". You'l see "Registration successfull"
3. Click "Generate a private key" and download the *.private-key.pem file
4. `cat *.private-key.pem | aws secretsmanager create-secret --name private-key --secret-string file:///dev/stdin`

### Logs

To read logs:

```sh
aws logs describe-log-groups
aws logs tail                                  /aws/lambda/auto-merge-dependabot-prs-AutoMergeDependabotPRsGi-YVZ8zJNokIL3
aws logs describe-log-streams --log-group-name /aws/lambda/auto-merge-dependabot-prs-AutoMergeDependabotPRsGi-YVZ8zJNokIL3
aws logs get-log-events       --log-group-name /aws/lambda/auto-merge-dependabot-prs-AutoMergeDependabotPRsGi-YVZ8zJNokIL3 --log-stream-name '2025/05/17/[$LATEST]54e6bb5924fd4680a2a832dc21b882ad'
```

### Other useful commands

```sh
# Test locally (doesn't work very well because of lack of AWS Secrets Manager)
sam build --beta-features && sam local start-api
curl -vvv --data-binary @tests/webhook-data/pull-request-opened-by-dependabot/payload.json -H "X-Hub-Signature-256: a" -H "Content-Type: application/json" -H "X-GitHub-Event: pull_request" http://127.0.0.1:3000/webhook

# Test against AWS deployment
api_id=$(aws apigateway get-rest-apis | jq --raw-output '.items[0].id')
curl -vvv --data-binary @tests/webhook-data/pull-request-opened-by-dependabot/payload.json -H "X-Hub-Signature-256: sha256=a" -H "Content-Type: application/json" -H "X-GitHub-Event: pull_request" https://$api_id.execute-api.eu-west-1.amazonaws.com/Prod/webhook

# Run tests
cargo test --manifest-path=webhook/Cargo.toml
```
