# Plan: self-hosted AWS canary credentials for our EC2 fleet

## Goal
Put a unique fake AWS access key on each EC2 server (under 50). If anyone ever
uses one, we get an alert within minutes saying which server it was taken from,
the source IP and what they tried. Everything runs in our own AWS organisation,
so no third-party vendor sees our infrastructure.

## Non-negotiables
- Must never break real workloads. Servers keep using their instance role.
- Must never go silent without us knowing. There is a weekly end-to-end
  self-test that alerts if it does NOT fire.
- Nothing visible to an attacker may say "canary", "honey", "decoy" or "test".
- Get sign-off from whoever owns security/infra before deploying. Tell a small
  named group so they don't trip it. Do not announce it widely.

## Architecture
1. **A dedicated, empty AWS account** in our Organization (for example
   "legacy-backup" or "data-archive-prod"). It runs no workloads, so ANY API
   call by an IAM user in it is an alert. Root has MFA and only the security
   admin can access it.
2. **One IAM user and access key per server** in that account. The user has no
   permissions, plus an explicit Deny-all policy, and we can also add an SCP
   that denies everything. Denied calls are still logged, which is what we want.
   - Use believable names like `svc-backup-sync` or `deploy-artifacts`.
     **Important:** AWS AccessDenied errors show the attacker the full user ARN,
     including the account ID and user name, so the names must look real.
   - Keep the key-to-server mapping in our security account (a DynamoDB table or
     SSM Parameter Store), not on the servers.
3. **Detection:** a multi-region CloudTrail trail in the canary account,
   recording management events (both Read and Write), sent to CloudWatch Logs.
   A subscription filter on `userIdentity.type = "IAMUser"` triggers a Lambda.
   The Lambda looks up the key ID, adds the server, IP, user agent, action,
   region and time, and posts to Slack and email (or PagerDuty).
   - STS and IAM events land in us-east-1, so the trail must cover all regions.
   - Expect a few minutes of delay. Measure it during testing (Phase 2).
4. **Deployment to servers:** an SSM Run Command / State Manager association
   targeted by tag writes the key into a believable place:
   - `~/.aws/credentials` for root and the main login user (ubuntu/ec2-user),
     as a **named profile** such as `[backup-prod]`.
   - Optionally also a plausible `.env` or config file, if it fits our setup.
   - New servers: an SSM association on a tag, or launch template user-data
     that requests a fresh key.

## Critical gotcha: NEVER put the fake key in `[default]` or AWS_* env vars
The AWS SDK looks for credentials in this order: environment variables, then the
`[default]` profile in the credentials file, then the instance role. A canary in
`[default]` would override the instance role, so every app on the box would break
and the alerts would fire constantly. Use a named profile only. Also check that
no one sets `AWS_PROFILE` to it.

## Phases
**Phase 0 - approval and design (half a day)**
- Agree an owner, where alerts go and who responds. Pick the account name and
  user naming style.

**Phase 1 - build (1 day, as code: Terraform or CDK in our own repo)**
- Canary account, trail, log group, filter, Lambda, alert routing.
- A script to create and revoke a key for a given server and record the mapping.
- One designated TEST key.

**Phase 2 - prove detection before trusting it (half a day)**
Use the test key from a laptop. For each call below, record whether it alerts
and how long it takes:
- `aws sts get-caller-identity`
- `aws s3 ls`
- `aws iam get-user`
- `aws ec2 describe-instances --region eu-west-2` and one other region
- `aws sts get-access-key-info` run with OUR OWN credentials against the canary
  key. This one runs in the caller's account, so we expect NO alert. Record it
  as a known blind spot: an attacker can learn the account ID without tripping
  anything, which is why the naming above matters.

Write the results down. Do not assume an API call is logged; prove it.

**Phase 3 - pilot (3 non-critical servers, 1 week)**
- Deploy, confirm the apps are unaffected and there are no false alerts.
- Find anything on the boxes that lists or reads profiles (backup agents,
  scanners, dev tooling) and record it as an expected false positive, or move
  the canary.

**Phase 4 - rollout to all servers via SSM**
- Confirm every server has its key (SSM compliance or inventory).
- Check that new instances get one automatically.

**Phase 5 - make it impossible to go quiet**
- A weekly scheduled job (EventBridge Scheduler + Lambda in a DIFFERENT account)
  uses the test key and checks the alert arrived within 15 minutes. If it
  didn't, send a separate "canary pipeline broken" alert.
- A monthly check that the number of keys equals the number of running servers.

**Phase 6 - runbook (one page)**
When an alert fires:
1. Is it the test key, or a known false positive? Stop here if so.
2. Identify the server from the mapping. Treat it as compromised.
3. Isolate it (a quarantine security group, keep it running), snapshot its
   disks, and preserve its logs.
4. Rotate all real secrets that server could reach (instance role sessions,
   app secrets, DB passwords, SSH keys).
5. Revoke and reissue that server's canary key after the investigation.
6. Look at the source IP and user agent and check other logs for the same IP.

## Cost
Close to zero. The first copy of management events in CloudTrail is free,
CloudWatch Logs volume will be tiny, and the Lambda stays inside the free tier.

## Out of scope for now (possible later additions)
- Fake SSH keys. Detecting their use needs a honeypot host, which is more work.
- Canaries in CI/CD secrets and code repos (the same key mechanism works there).
- Fake DB credentials, documents and URLs: self-hosted Thinkst Canarytokens
  (`thinkst/canarytokens-docker`) covers these if we want them later.

## Definition of done
- Every server has a unique key in a named profile.
- The Phase 2 results are written down, including blind spots.
- The weekly self-test is green and has been seen failing once on purpose.
- The runbook is written and the alert owner has read it.