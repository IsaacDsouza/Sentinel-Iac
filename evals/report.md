# Sentinel IaC Eval Report

**Generated:** 2026-06-21 18:54 UTC

**Threshold:** >= 80% recall

## Summary

| Fixture | Expected | Detected | Recall | Status |
|---------|----------|----------|--------|--------|
| terragoat | 5 | 3 | 60.0% | FAIL |
| k8s-goat | 2 | 0 | 0.0% | FAIL |
| **Overall** | **7** | **3** | **42.9%** | **FAIL** |

**Total raw findings across all scanners:** 79

## Details

### terragoat (FAIL) — 60.0%

- **Expected:** 5 rules
- **Detected:** 3 rules
- **Recall:** 60.0%

**Detected rules:**

- `AWS-0086`
- `AWS-0087`
- `AWS-0089`
- `AWS-0090`
- `AWS-0091`
- `AWS-0092`
- `AWS-0093`
- `AWS-0104`
- `AWS-0107`
- `AWS-0124`
- `AWS-0132`
- `AWS-0143`
- `CKV2_AWS_5`
- `CKV2_AWS_6`
- `CKV2_AWS_61`
- `CKV2_AWS_62`
- `CKV_AWS_144`
- `CKV_AWS_145`
- `CKV_AWS_18`
- `CKV_AWS_20`
- `CKV_AWS_21`
- `CKV_AWS_23`
- `CKV_AWS_24`
- `CKV_AWS_25`
- `CKV_AWS_260`
- `CKV_AWS_273`
- `CKV_AWS_274`
- `CKV_AWS_277`
- `CKV_AWS_382`
- `CKV_AWS_40`
- `CKV_AWS_53`
- `CKV_AWS_54`
- `CKV_AWS_55`
- `CKV_AWS_56`

**Missing rules:**

- `CKV_AWS_52` (medium) — aws_security_group.wide_open
- `CKV_AWS_89` (medium) — aws_iam_user_policy_attachment.admin_access

### k8s-goat (FAIL) — 0.0%

- **Expected:** 2 rules
- **Detected:** 0 rules
- **Recall:** 0.0%

**Detected rules:**

- `CKV2_K8S_6`
- `CKV_K8S_10`
- `CKV_K8S_11`
- `CKV_K8S_12`
- `CKV_K8S_13`
- `CKV_K8S_14`
- `CKV_K8S_16`
- `CKV_K8S_17`
- `CKV_K8S_19`
- `CKV_K8S_20`
- `CKV_K8S_21`
- `CKV_K8S_22`
- `CKV_K8S_23`
- `CKV_K8S_28`
- `CKV_K8S_29`
- `CKV_K8S_31`
- `CKV_K8S_37`
- `CKV_K8S_38`
- `CKV_K8S_40`
- `CKV_K8S_43`
- `CKV_K8S_8`
- `CKV_K8S_9`
- `KSV-0001`
- `KSV-0003`
- `KSV-0004`
- `KSV-0009`
- `KSV-0010`
- `KSV-0011`
- `KSV-0012`
- `KSV-0013`
- `KSV-0014`
- `KSV-0015`
- `KSV-0016`
- `KSV-0017`
- `KSV-0018`
- `KSV-0020`
- `KSV-0021`
- `KSV-0030`
- `KSV-0036`
- `KSV-0104`
- `KSV-0105`
- `KSV-0106`
- `KSV-0110`
- `KSV-0117`
- `KSV-0118`

**Missing rules:**

- `CKV_K8S_1` (high) — Pod/insecure-pod
- `CKV_K8S_2` (high) — Pod/insecure-pod

## Scanner Breakdown

| Engine | Findings |
|--------|----------|
| checkov | 61 |
| hadolint | 0 |
| kube-score | 0 |
| opa-conftest | 0 |
| trivy | 54 |

---

**Result: FAIL** — recall 42.9% < 80%
