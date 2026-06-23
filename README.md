# Sentinel IaC

Scans Terraform, Kubernetes manifests, and Dockerfiles for security misconfigurations. Runs five industry scanners, normalizes results to SARIF, then optionally explains findings with an LLM, maps them to NIST 800-53 controls (via RAG), and generates validated patches.

**The LLM is not the scanner.** Detection is done by deterministic engines running in Docker containers. The LLM explains, maps compliance, and proposes fixes. Every fix is verified by re-running the scanner before it's shown.

## Quickstart

```bash
# Install
pip install -e .

# Scan a directory
sentinel scan ./evals/fixtures/terragoat

# Scan + LLM enrichment (explanation, compliance, prioritization)
sentinel scan --enrich ./evals/fixtures/terragoat

# Generate and validate fixes
sentinel fix ./evals/fixtures/terragoat

# Apply validated fixes
sentinel fix ./evals/fixtures/terragoat --write
```

## How it works

Five Docker containers (Checkov, Trivy, kube-score, hadolint, OPA) scan your IaC files. Results are merged into a single SARIF document, deduplicated across engines (equivalent rules like `CKV_AWS_18` ↔ `AVD-AWS-0089` are merged). You get a severity-colored table and a `.sarif` file.

When `--enrich` is passed, findings go through three LLM stages:
- **Explain** — describes the issue and attacker scenario in plain language
- **Compliance** — retrieves relevant NIST 800-53 controls via pgvector cosine similarity, then asks the LLM to rank them (it never invents control IDs)
- **Prioritize** — scores 0-100 by blast radius (public exposure, privilege level, data sensitivity)

When `fix` is run, the LLM proposes a patch. The scanner re-runs against the patched file. If the finding is gone, the patch is surfaced. If not, it retries (up to 5 iterations). Only validated patches reach `--write`.

### Why validation matters

LLMs hallucinate wrong attributes, delete closing braces, write resource blocks that don't exist, and miss root causes. The validation loop catches all of these. It's the difference between a tool that looks correct and one that actually works.

## CLI

| Command | What it does |
|---------|-------------|
| `sentinel scan <path>` | Run all scanners, print table, write SARIF |
| `sentinel scan --enrich <path>` | + LLM enrichment pipeline |
| `sentinel fix <path>` | Scan + generate validated patches |
| `sentinel fix <path> --write` | Apply validated patches to disk |
| `sentinel eval-report` | Check detection recall against golden fixtures |
| `sentinel rag ingest` | Load NIST 800-53 into pgvector |
| `sentinel rag query <text>` | Semantic search compliance controls |

## API & Frontend

```bash
docker compose up --build
# Web UI at http://localhost:3000
# API at http://localhost:8000
# Swagger docs at http://localhost:8000/docs
```

Endpoints: trigger scans, list history, live SSE stream, findings query, dashboard stats. Auth via `X-API-Key` header (disabled when `API_KEY` env var is empty).

## Configuration

Set via `.env` or environment variables:

| Variable | Default | Notes |
|----------|---------|-------|
| `DATABASE_URL` | `postgresql+asyncpg://...` | PostgreSQL with pgvector |
| `OPENAI_API_KEY` | — | Required for enrichment/fix |
| `OPENAI_BASE_URL` | — | NVIDIA NIM: `https://integrate.api.nvidia.com/v1` |
| `OPENAI_MODEL` | `meta/llama-3.3-70b-instruct` | |
| `API_KEY` | — | API auth (empty = no auth) |
| `EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | Local sentence transformer |

## LLM Provider

Uses OpenAI-compatible APIs. NVIDIA NIM free tier works out of the box (40 req/min). Point `OPENAI_BASE_URL` at any `/chat/completions` endpoint.

## Scanners

| Engine | Docker image | Covers |
|--------|-------------|--------|
| Checkov | `bridgecrew/checkov` | Terraform, K8s, Docker, CloudFormation, ARM |
| Trivy | `aquasec/trivy` | Terraform, K8s, Docker |
| kube-score | `zegl/kube-score` | Kubernetes manifests |
| hadolint | `hadolint/hadolint` | Dockerfiles |
| OPA/Conftest | `openpolicyagent/conftest` | Any (custom policies) |

Scanners run as ephemeral containers (`--network none --read-only`, 512 MB RAM, 1 CPU). Falls back to local binary if Docker isn't available.

## Project Structure

```
src/sentinel/       # Core: scanners, enrichment, remediation, API, CLI
frontend/           # React + Vite dashboard
deploy/helm/        # Kubernetes Helm chart (probes, HPA, network policies)
evals/              # Golden fixtures + eval harness
.github/            # CI workflow + composite action
```

## What this isn't

- Not a SaaS. Not a cloud service. No telemetry. No accounts.
- The Helm chart exists if you want to run it as an internal service on K8s, but the CLI does everything the API does.
- The LLM is optional. Scan-only mode doesn't need any API keys.

## License

Apache 2.0
