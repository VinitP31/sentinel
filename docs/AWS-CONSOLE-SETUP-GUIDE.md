# Setting Up AWS for Sentinel (Console Only)

This guide covers the AWS configuration required for the current Sentinel POC — using only the AWS Console, no CLI, no code changes. You'll finish with temporary credentials you paste into Sentinel, and you pick which discovered accounts to audit directly in the app.

## Minimum setup, at a glance

1. In **every account you want audited**: create one IAM role (`AuditReadOnlyRole`) that trusts your Management Account and holds one read-only policy. (Part 1)
2. In your **Management Account**: create one policy that lets your identity assume those roles and list Organization accounts. (Part 2)
3. Get **temporary credentials** for that Management Account identity from the AWS Console. (Part 3)
4. Open Sentinel, paste those credentials, **select which discovered accounts to audit**, and run. (Part 4)

Nothing here requires editing Sentinel's code — account selection happens entirely in the app, from whatever AWS Organizations actually returns.

## Setup topology

```
Management Account
        │
        │ organizations:ListAccounts
        │
        ├───────────────┐
        ↓               ↓
      PROD             DEV            (any number of accounts — two shown as an example)
        │               │
 AuditReadOnlyRole  AuditReadOnlyRole
        ↑               ↑
        └──── sts:AssumeRole ────┘
```

```
Management Account temporary credentials
                ↓
             Sentinel
                ↓
        Discover accounts (Organizations)
                ↓
        You select which accounts to audit
                ↓
        Sentinel assumes AuditReadOnlyRole per selected account
                ↓
        Audit runs, results shown in the dashboard
```

---

## What you're setting up

Two things, in AWS:

1. **A read-only audit role in every account you want audited** — each one explicitly trusts your Management Account.
2. **A way to get short-lived credentials for your Management Account** — pasted into Sentinel, never stored anywhere permanent.

With the recommended temporary-credential setup, Sentinel does not receive standing access. The credentials expire on their own.

---

## Prerequisites

- AWS Organizations must already be set up, and the identity you'll give Sentinel credentials for must belong to the organization's **Management Account**. Sentinel uses `organizations:ListAccounts` to discover the accounts available for selection in Part 4.
- Console access with permission to create IAM policies and roles **in each target account** (Part 1), *and* permission to create a policy and attach it to your Sentinel identity **in the Management Account** (Part 2) — these are two different accounts, so you may need access to both, possibly from different people depending on how your organization is set up.
- The account IDs of every account you want audited (these are the accounts the role in Part 1 gets created in).
- If you use AWS IAM Identity Center (formerly AWS SSO) for console access, keep that in mind for Part 3 — it's the supported console-only path for genuinely temporary credentials.

---

## Part 1 — Create the read-only audit role in each target account

Do this once **in every account you want Sentinel to audit** (not in the Management Account).

### 1.1 Create the permissions policy

1. Sign in to the AWS Console **for the target account**.
2. Go to **IAM → Policies → Create policy**.
3. Switch to the **JSON** editor and paste:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SentinelReadOnlyAccess",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountAuthorizationDetails",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetServiceLastAccessedDetails",
        "cloudtrail:LookupEvents",
        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

4. Click **Next**, name it `POC-AWS-IAM-Audit-ReadOnly` (or your own naming convention), and create it.

This is the exact and complete list of AWS actions Sentinel's collectors call — nothing broader, nothing write-capable.

### 1.2 Create the role

1. Go to **IAM → Roles → Create role**.
2. Choose **Custom trust policy**, and paste (replace `MANAGEMENT_ACCOUNT_ID` with your actual Management Account's 12-digit ID):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::MANAGEMENT_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

   This is what makes the trust real — only your Management Account can ever assume this role. (Using `:root` here trusts the whole account; if you want to restrict it to one specific IAM user or role in the Management Account, use that identity's exact ARN instead of `:root`.)

3. On the permissions step, attach the `POC-AWS-IAM-Audit-ReadOnly` policy you just created.
4. Name the role exactly **`AuditReadOnlyRole`**.
5. Create the role.

> **Do not use a different role name.** Sentinel's current code assumes the exact name `AuditReadOnlyRole` in every target account — a differently named role will never be found, and every account using it will fail with "Could not assume role." If you need a different name, someone has to change it in Sentinel's source (`ROLE_NAME` in `src/orchestrator.py`) first.

**Repeat Part 1 for every account you want audited.**

**Worked example** (illustrative account IDs — use your own): with a Management Account of `111111111111` and two target accounts, `222222222222` (call it Production) and `333333333333` (call it Development), the trust policy's `Principal.AWS` in both target accounts would be `arn:aws:iam::111111111111:root`, and the resulting roles would be `arn:aws:iam::222222222222:role/AuditReadOnlyRole` and `arn:aws:iam::333333333333:role/AuditReadOnlyRole`.

---

## Part 2 — Give your Management Account identity permission to use it

Do this once, **in the Management Account**.

The identity whose temporary credentials you'll eventually paste into Sentinel needs two permissions:

1. `sts:AssumeRole`, scoped to the `AuditReadOnlyRole` in each target account.
2. `organizations:ListAccounts` (this is what populates the list of accounts Sentinel lets you select from — without it, there's nothing to choose in Part 4).

Create a policy for this in the Management Account:

1. **IAM → Policies → Create policy**, JSON editor:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeAuditRoles",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::TARGET_ACCOUNT_ID_1:role/AuditReadOnlyRole",
        "arn:aws:iam::TARGET_ACCOUNT_ID_2:role/AuditReadOnlyRole"
      ]
    },
    {
      "Sid": "ListOrgAccounts",
      "Effect": "Allow",
      "Action": "organizations:ListAccounts",
      "Resource": "*"
    }
  ]
}
```

   Replace the `Resource` ARNs with the actual account IDs from Part 1 — continuing the worked example above, that's `arn:aws:iam::222222222222:role/AuditReadOnlyRole` and `arn:aws:iam::333333333333:role/AuditReadOnlyRole`. Name the policy something like `Sentinel-Management-Account-Access`.

2. Attach this policy to the identity you'll sign in as when getting temporary credentials in Part 3 — either an IAM user, or an IAM Identity Center permission set.

---

## Part 3 — Get temporary credentials from the Console (no CLI)

This is the step that gets you the Access Key ID / Secret Access Key / Session Token Sentinel's "Paste Temporary Credentials" screen asks for.

### Recommended: IAM Identity Center

This is the supported console-only path for obtaining **actual temporary credentials** — AWS Identity Center–issued credentials are temporary by design and are what AWS itself recommends over long-lived IAM user keys.

1. Go to your organization's AWS access portal (the URL your admin gave you — looks like `https://your-org.awsapps.com/start`).
2. Sign in, find the Management Account, and click it to expand the available roles/permission sets.
3. Next to the permission set that has the policy from Part 2, click **"Command line or programmatic access."**
4. You'll see a page with **Access key ID**, **Secret access key**, and **Session token** — already temporary, already expiring. Copy all three.
5. Paste them directly into Sentinel's **Access Key ID**, **Secret Access Key**, and **Session Token** fields.

### If IAM Identity Center is not available

Sentinel can technically accept a plain IAM user's access key here, but **this is not a temporary credential** — it's a long-lived key that doesn't expire on its own, and it doesn't satisfy this guide's actual goal of console-only *temporary* access. Treat this only as a stopgap for a controlled POC/testing environment, not as an equivalent alternative to Identity Center.

1. Sign in to the Management Account Console as the IAM user with the Part 2 policy attached.
2. Go to **IAM → Users → (your user) → Security credentials tab**.
3. Under **Access keys**, click **Create access key**.
4. Choose **Third-party service** as the use case, create it, and copy the **Access key ID** and **Secret access key** shown (this is the only time the secret is shown).
5. Paste them into Sentinel's Access Key ID / Secret Access Key fields — **leave Session Token blank**, since this kind of key doesn't have one.

You're responsible for rotating/deleting this key yourself afterward (same **Security credentials** tab) — Sentinel has no way to expire it for you.

---

## Part 4 — Discover accounts and run the audit

1. Open Sentinel (`streamlit run app.py`).
2. Paste the credentials from Part 3 into the corresponding fields. They're masked by default; use the reveal toggle to double-check them if needed.
3. Click **Connect & Discover Accounts**. Sentinel verifies the identity, then lists every account visible to it via AWS Organizations — nothing is audited yet at this point.
4. A checkbox appears for each discovered account, showing its name, account ID, and status. Only accounts you actually have an `AuditReadOnlyRole` set up in (Part 1) will succeed — select those.
5. Click **Run Audit**. Sentinel assumes `AuditReadOnlyRole` in each selected account and runs the audit against exactly the accounts you checked — nothing more.

You need at least one account selected to proceed — if none are checked, Sentinel shows a message and won't start the audit.

### What success looks like

```
Connect & Discover Accounts
        ↓
Production — 222222222222 (ACTIVE)
Development — 333333333333 (ACTIVE)

Select accounts:
☑ Production
☑ Development

Run Audit
        ↓
Audit complete
        ↓
Overview / Findings / Accounts / Graph
```

If an account appears in the discovered list but the audit fails for it with "Could not assume role" / AccessDenied, that account was discovered successfully — the problem is specifically that its `AuditReadOnlyRole` setup (Part 1) is missing or incorrect, not a Sentinel or credential problem.

---

## Data sent outside AWS

One stage of the audit sends each finding, plus that finding's supporting evidence, to OpenAI's API to generate a plain-language explanation. No AWS credentials are ever included in that call — only the finding data itself (principal name, rule, policy attribution, evidence summary). If that's a concern for your environment, this is worth discussing before running a real audit; it isn't something this setup guide can configure around.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| "Could not assume role" / AccessDenied for a selected account | The trust policy in that target account doesn't list your Management Account correctly, or the Management Account identity is missing the `sts:AssumeRole` permission from Part 2 for that specific account's role ARN. |
| No accounts discovered / discovery fails | AWS Organizations isn't enabled for this Management Account, or the identity lacks `organizations:ListAccounts`. Sentinel shows this as a clear message and won't offer any accounts to select. |
| An account you expected isn't in the discovered list | It exists outside this AWS Organization, or the Management Account identity can't see it via `organizations:ListAccounts` — this is an AWS-side visibility issue, not something to fix in Sentinel. |
| Credentials rejected immediately | Access key / secret / session token were copied incorrectly, or (Identity Center path) they've already expired — get a fresh set. |
| An account is selected but fails during the audit | Part 1 wasn't completed for that specific account — check the role name is exactly `AuditReadOnlyRole` and its trust policy names your Management Account. |

---

## Cleaning up

Everything created here is easy to remove and touches nothing else in your account:

- Delete the `AuditReadOnlyRole` role (and its policy) in any target account to fully revoke Sentinel's access to it.
- Delete or deactivate the IAM user access key from Part 3 ("If IAM Identity Center is not available") if you used it.
- Sentinel never writes to AWS, so there's nothing else it could have changed to clean up.
