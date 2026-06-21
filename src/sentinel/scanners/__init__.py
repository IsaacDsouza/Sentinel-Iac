from sentinel.scanners.base import Scanner, ScanResult
from sentinel.scanners.checkov import CheckovScanner
from sentinel.scanners.hadolint import HadolintScanner
from sentinel.scanners.kube_score import KubeScoreScanner
from sentinel.scanners.opa import OpaScanner
from sentinel.scanners.trivy import TrivyScanner

__all__ = [
    "Scanner",
    "ScanResult",
    "CheckovScanner",
    "TrivyScanner",
    "KubeScoreScanner",
    "HadolintScanner",
    "OpaScanner",
]

SCANNERS: list[type[Scanner]] = [
    CheckovScanner,
    TrivyScanner,
    KubeScoreScanner,
    HadolintScanner,
    OpaScanner,
]
