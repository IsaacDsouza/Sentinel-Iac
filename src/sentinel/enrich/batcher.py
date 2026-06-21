from sentinel.config import get_config
from sentinel.models import Finding


def _estimate_tokens(text: str) -> int:
    return len(text) // 4 + 1


class TokenBudgetBatcher:
    def __init__(self, budget: int | None = None) -> None:
        self.budget = budget or get_config().enrichment_batch_token_budget

    def batch(self, findings: list[Finding]) -> list[list[Finding]]:
        batches: list[list[Finding]] = []
        current: list[Finding] = []
        current_tokens = 0

        for finding in findings:
            text = f"{finding.title} {finding.raw_description}"
            tokens = _estimate_tokens(text)

            if current_tokens + tokens > self.budget and current:
                batches.append(current)
                current = []
                current_tokens = 0

            current.append(finding)
            current_tokens += tokens

        if current:
            batches.append(current)

        return batches
