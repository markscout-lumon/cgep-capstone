# Acme Health: GRC Engineering Capstone Write-up

## Primary framework
[Name your framework in the first paragraph. Three sentences on why it fits
this telehealth system better than the other two.]

## Control coverage
[For each gap from GAPS.md: which control it maps to, and whether you closed
it in Terraform, enforced it in policy, or both. A table works well here.]

## Control coverage

Primary framework is the HIPAA Security Rule. NIST SP 800-66 Rev. 2 is the implementation catalog (FRAMEWORKS.md): each 164.x standard is a 800-66 section. Policies declare the HIPAA ID; OSCAL `source` is 800-66r2; `props` carry the 800-66 section. 800-66 does not invent new control IDs like SC-28; the section *is* the overlay.

| Gap | What it is | HIPAA | NIST SP 800-66 Rev. 2 | Terraform | Policy | Layer |
|---|---|---|---|---|---|---|
| GAP-01 | S3 SSE-S3 default, not a customer CMK | 164.312(a)(2)(iv) Encryption and decryption | **5.3.1** Access Control (§ 164.312(a)); Table 21 key activity 8 (automatic logoff and encryption and decryption) | Closed — CMK `phi` + SSE-KMS on the uploads bucket | Planned — fail if default encryption is not SSE-KMS with a CMK | Both |
| GAP-02 | DynamoDB AWS-owned key | 164.312(a)(2)(iv) | **5.3.1** Access Control; same encryption-and-decryption implementation spec | Closed — table `server_side_encryption` uses `aws_kms_key.phi` | Planned — fail if the table has no customer `kms_key_arn` | Both |
| GAP-03 | No `aws:SecureTransport` deny | 164.312(e)(1) Transmission security | **5.3.5** Transmission Security (§ 164.312(e)(1)); Table 25 (integrity controls and encryption in transit) | Closed on the passing PR — `aws_s3_bucket_policy.uploads` Deny HTTP. PR #1 left it open so the gate failed | Fail if the bucket policy does not deny HTTP | Both |
| GAP-04 | S3 versioning off | 164.308(a)(7) Contingency plan | **5.1.7** Contingency Plan (§ 164.308(a)(7)); Table 14 data backup plan 164.308(a)(7)(ii)(A) | Closed — `aws_s3_bucket_versioning` `Enabled` | Planned — fail if versioning is not `Enabled` | Both |
| GAP-05 | Lambda not in the VPC | 164.312(e)(1) | **5.3.5** Transmission Security — 800-66 has no separate “boundary” section; private-subnet placement is how we limit who can intercept PHI in transit | Partial — `vpc_config` on private subnets + egress-only SG. ENI IAM and NAT/endpoints not done | Planned — fail if the function has no `vpc_config` | Both (partial TF) |

## Design decisions
[Walk each decision from the brief: region, Object Lock mode, apply-on-merge
vs manual gate, single vs separate account, Terraform-vs-policy split.
For each, state what you chose and the trade-off you accepted.]

Customer CMK with AWS automatic rotation at 365 days. Envelope encryption already uses per-object data keys; annual CMK rotation limits the lifetime of wrapping material without downtime or re-encryption. 90 days would be policy theater for this architecture.

## How the pipeline produces evidence
[Trace one run end to end: PR opened → gate → apply → sign → vault.
Name the run ID an assessor can verify.]

## What I didn't get to

I stopped after GAP-01 through GAP-05 so the easy wins: encryption, TLS detection, versioning, and Lambda placement had worked.

| Gap | What it is | HIPAA | NIST SP 800-66 Rev. 2 | Terraform | Policy | Layer |
|---|---|---|---|---|---|---|
| GAP-06 | No reserved concurrency, DLQ, or X-Ray | 164.308(a)(1) information system activity review | **5.1.1** Security Management Process (§ 164.308(a)(1)) | Open | Not in this submission | Next sprint |
| GAP-07 | Lambda role allows `dynamodb:*` and `s3:*` | 164.312(a)(1) access control | **5.3.1** Access Control (§ 164.312(a)); also **5.1.4** Information Access Management (§ 164.308(a)(4)) | Open | Not in this submission | Next sprint |
| GAP-08 | API Gateway has no access logs, throttling, or WAF | 164.312(b) audit controls | **5.3.2** Audit Controls (§ 164.312(b)); Table 22 | Open | Not in this submission | Next sprint |

## Trade-offs and what I'd do with another sprint
Another sprint would do GAP-07 first: the intake role can still read, overwrite, or delete PHI. Then a DLQ plus reserved concurrency (GAP-06), then API access logs (GAP-08). I also still owe GAP-05 its working path — VPC ENI IAM and NAT or VPC endpoints — before I would call the boundary complete.