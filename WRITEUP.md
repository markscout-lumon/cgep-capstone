# Acme Health: GRC Engineering Capstone Write-up

## Primary framework

Primary framework is the HIPAA Security Rule. This workload is a telehealth intake API that stores patient submissions and attachments, which is PHI, so HIPAA is the law that actually applies. SOC 2 would help if the next buyer were an enterprise security questionnaire, and CMMC L2 would help if Acme were chasing a federal pilot, but neither is why this system exists. NIST SP 800-66 Rev. 2 is the implementation catalog: it walks each 164.x standard and does not invent new IDs like SC-28. Policies declare the HIPAA citation; OSCAL `source` is the 800-66r2 CPRT catalog; `props` carry the 800-66 section.

## Control coverage

In scope: GAP-01 through GAP-05. GAP-06 through GAP-08 are deferred.

| Gap | What it is | HIPAA | NIST SP 800-66 Rev. 2 | Terraform | Policy | Layer |
|---|---|---|---|---|---|---|
| GAP-01 | S3 SSE-S3 default, not a customer CMK | 164.312(a)(2)(iv) Encryption and decryption | **5.3.1** Access Control (§ 164.312(a)); Table 21 key activity 8 | Closed — CMK `phi` + SSE-KMS on the uploads bucket | `policies/gap01_s3_cmk.rego` fails if default encryption is not SSE-KMS with a CMK | Both |
| GAP-02 | DynamoDB AWS-owned key | 164.312(a)(2)(iv) | **5.3.1** same encryption-and-decryption implementation spec | Closed — table `server_side_encryption` uses `aws_kms_key.phi` | `policies/gap02_ddb_cmk.rego` fails if the table has no customer `kms_key_arn` | Both |
| GAP-03 | No `aws:SecureTransport` deny | 164.312(e)(1) Transmission security | **5.3.5** Transmission Security (§ 164.312(e)(1)); Table 25 | Closed on the passing PR — `aws_s3_bucket_policy.uploads` Deny HTTP. PR #1 left it open so the gate failed | `policies/gap03_s3_tls.rego` fails if the bucket policy does not deny HTTP | Both |
| GAP-04 | S3 versioning off | 164.308(a)(7) Contingency plan | **5.1.7** Contingency Plan (§ 164.308(a)(7)); Table 14 data backup plan | Closed — `aws_s3_bucket_versioning` `Enabled` | `policies/gap04_s3_versioning.rego` fails if versioning is not `Enabled` | Both |
| GAP-05 | Lambda not in the VPC | 164.312(e)(1) | **5.3.5** — 800-66 has no separate boundary section; private-subnet placement is how we limit who can intercept PHI in transit | Partial — `vpc_config` on private subnets + egress-only SG. NAT or VPC endpoints not done | `policies/gap05_lambda_vpc.rego` fails if the function has no `vpc_config` | Both (partial TF) |

The component also records **5.3.2** Audit Controls (§ 164.312(b)) for the wrap that is not a named gap: CloudTrail, the Object Lock vault, and the signed pipeline. That is Terraform plus CI, not a Rego detector.

## Design decisions

**Region: `us-east-1`.** Same region as the inherited starter and the course labs. One region keeps KMS, Lambda, DynamoDB, and the vault in the same boundary. The trade-off is no multi-region failover; 800-66 5.1.7 backup here is S3 versioning, not a second region.

**Object Lock: GOVERNANCE, 30 days.** COMPLIANCE would make a lab mistake irreversible. GOVERNANCE still WORM-protects evidence against the pipeline role; an account admin can still recover. Retention is long enough to show a grader a signed run and short enough that leftover objects do not live forever.

**Apply on merge to main, not a manual gate.** PRs only plan and Conftest. Merge to `main` applies the saved plan, then Cosign-signs and uploads. The trade-off is that a green PR deploys without a second human click. That is the point of the gate: if Conftest is red, apply does not run.

**Single AWS account.** The starter, the vault, CloudTrail, and the OIDC apply role share account `140421379759`. A separate evidence account would isolate the vault better and is more IAM and billing than this sprint. The vault policy still denies `s3:DeleteBucket` except the account root.

**Terraform vs policy split.** Anything that is a sibling resource or a nested block we could own (CMK, SSE-KMS, versioning, TLS deny, Lambda `vpc_config`) is closed in Terraform so the live system is actually hardened. Rego watches the plan so a later change cannot silently drop those settings. GAP-03 was the exception on purpose for one PR: Terraform left HTTP open, policy failed closed, then the TLS deny shipped on PR #2.

**CMK rotation: 365 days.** Envelope encryption already uses per-object data keys; annual CMK rotation limits the lifetime of wrapping material without downtime or re-encryption. 90 days would be policy theater for this architecture.

## How the pipeline produces evidence

One workflow, five named steps: plan → Conftest → apply on merge → Cosign keyless (GitHub OIDC) → upload to `acme-health-intake-grc-evidence-vault-160174f2`.

1. Open a PR against `main`. The job plans from remote state (`acme-health-intake-tfstate-140421379759`) and runs `scripts/policy-gate.sh`.
2. If Conftest fails, apply is skipped. Sign and upload still run so the fail is in the vault. **PR #1** ([run 35463292244](https://github.com/markscout-lumon/cgep-capstone/actions/runs/35463292244)) is that path: only GAP-03 denied. Object: `s3://acme-health-intake-grc-evidence-vault-160174f2/runs/35463292244/evidence-35463292244-24797970d2f2569563ba54f9bd20dca0af09aae1.tar.gz`.
3. **PR #2** added the TLS deny, Conftest passed ([run 35463544546](https://github.com/markscout-lumon/cgep-capstone/actions/runs/35463544546)), and the PR merged.
4. The `push` to `main` ran apply, then signed and uploaded. Assessor run: **[35463669806](https://github.com/markscout-lumon/cgep-capstone/actions/runs/35463669806)**. Bundle: `s3://acme-health-intake-grc-evidence-vault-160174f2/runs/35463669806/evidence-35463669806-9465e9d44a8c23c37dbf87c20620df16da7da95c.tar.gz`, plus `.sig.bundle` and `receipt.json`.

GitHub marked PR #1 merged after PR #2 landed because #2 contained #1's commits. PR #1 was never merged while red; the failed check on that PR is the blocked-gate evidence.

## OSCAL and the catalog

`oscal/component-definition.json` describes this intake API and the wrap, not a generic S3 module. `oscal/profiles/cge-p-minimum.json` selects 5.3.1, 5.3.5, 5.1.7, and 5.3.2.

NIST does not publish HIPAA or 800-66 as an official OSCAL catalog (they do for 800-53). **OSCAL** is the document format we wrote: component definition and profile, with UUIDs, Terraform addresses, ARNs, and vault evidence links. **CPRT** (Cybersecurity and Privacy Reference Tool) is NIST's machine-readable publication of 800-66 Rev. 2. The component `source` points at that CPRT catalog so the chain is starter → Rego → OSCAL → the catalog we declared, not 800-53.

## What I didn't get to

I stopped after GAP-01 through GAP-05 so encryption, TLS, versioning, and Lambda placement were real.

| Gap | What it is | HIPAA | NIST SP 800-66 Rev. 2 | Terraform | Policy | Layer |
|---|---|---|---|---|---|---|
| GAP-06 | No reserved concurrency, DLQ, or X-Ray | 164.308(a)(1) information system activity review | **5.1.1** Security Management Process (§ 164.308(a)(1)) | Open | Not in this submission | Next sprint |
| GAP-07 | Lambda role allows `dynamodb:*` and `s3:*` | 164.312(a)(1) access control | **5.3.1** Access Control; also **5.1.4** Information Access Management | Open | Not in this submission | Next sprint |
| GAP-08 | API Gateway has no access logs, throttling, or WAF | 164.312(b) audit controls | **5.3.2** Audit Controls (§ 164.312(b)); Table 22 | Open | Not in this submission | Next sprint |

## Trade-offs and what I'd do with another sprint

Another sprint would do GAP-07 first: the intake role can still read, overwrite, or delete PHI. Then a DLQ plus reserved concurrency (GAP-06), then API access logs (GAP-08). I also still owe GAP-05 its working path — NAT or VPC endpoints — before I would call the boundary complete.
