__version__ = "0.1.0"

from datashield.cli import app
from datashield.compliance import ComplianceVerifier, GDPRCompliance, HIPAACompliance
from datashield.config import DataShieldSettings, settings
from datashield.detectors import PatternMatcher, PIIDetector, SecretScanner, SensitiveClassifier
from datashield.privacy import DifferentialPrivacy, EpsilonCalculator, KAnonymity
from datashield.reporters import ConsoleReporter, HTMLReporter, JSONReporter
from datashield.sanitizers import Anonymizer, Minimizer, Redactor, Transformer
from datashield.scanner import Confidence, DataCategory, Finding, Scanner, ScanReport, Severity

try:
    from datashield.taxonomy import datashield_finding_to_taxonomy
except ImportError:
    datashield_finding_to_taxonomy = None  # type: ignore[assignment]

__all__ = [
    "app",
    "Scanner",
    "ScanReport",
    "Finding",
    "Severity",
    "Confidence",
    "DataCategory",
    "PIIDetector",
    "SecretScanner",
    "SensitiveClassifier",
    "PatternMatcher",
    "Anonymizer",
    "Redactor",
    "Minimizer",
    "Transformer",
    "DifferentialPrivacy",
    "KAnonymity",
    "EpsilonCalculator",
    "GDPRCompliance",
    "HIPAACompliance",
    "ComplianceVerifier",
    "ConsoleReporter",
    "JSONReporter",
    "HTMLReporter",
    "DataShieldSettings",
    "settings",
]
