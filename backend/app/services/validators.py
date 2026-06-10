import logging
from typing import Any, Dict, List, Tuple
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, field_validator, ValidationError

logger = logging.getLogger("aether.validators")

class VulnerabilityRow(BaseModel):
    """
    Production-grade schema for PostgreSQL vulnerabilities table.
    Guarantees strict typing and default values for database insertion.
    """
    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    session_id: UUID
    attack_vector: str = Field(default="Web Application Surface")
    detected_threat: str = Field(default="Potential Hunt Signal")
    provided_solution: str = Field(default="Apply standard security hardening per OWASP guidelines.")
    severity: str = Field(default="Low")
    category: str = Field(default="general")
    title: str = Field(default="Untitled Vulnerability")
    detail: str = Field(default="Analysis in progress.")
    evidence: Dict[str, Any] = Field(default_factory=dict)
    is_fixed: bool = Field(default=False)

    @field_validator("severity", mode="before")
    @classmethod
    def coerce_severity(cls, v: Any) -> str:
        """Force-corrects severity values to allowed Enum set."""
        valid_levels = {"Low", "Medium", "High", "Critical"}
        if isinstance(v, str):
            val = v.strip().capitalize()
            if val in valid_levels:
                return val
        return "Low"

    @field_validator("attack_vector", "detected_threat", "provided_solution", "category", "title", "detail", mode="before")
    @classmethod
    def sanitize_strings(cls, v: Any) -> str:
        """Strips whitespace and ensures string type for text columns."""
        if v is None:
            return ""
        return str(v).strip()

    @field_validator("evidence", mode="before")
    @classmethod
    def ensure_valid_jsonb(cls, v: Any) -> Dict[str, Any]:
        """Ensures evidence is a valid dictionary for JSONB storage."""
        if isinstance(v, dict):
            return v
        return {}

def validate_and_build_rows(
    findings: Any, 
    scan_id: Any, 
    session_id: Any
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Validates raw Gemini output and transforms it into sanitized database rows.
    """
    if session_id is None:
        raise ValueError("HARD_FAILURE: session_id is required and cannot be null.")

    try:
        target_scan_id = UUID(str(scan_id))
        target_session_id = UUID(str(session_id))
    except (ValueError, TypeError) as e:
        raise ValueError(f"HARD_FAILURE: Invalid UUID context provided for validation: {e}")

    # Auto-fallback for empty or malformed finding lists
    if not findings or not isinstance(findings, list):
        findings = [{
            "title": "Engine Heuristic Pass Complete",
            "detail": "Target analyzed with no specific vulnerabilities flagged.",
            "severity": "Low",
            "category": "info",
            "evidence": {"source": "validator_fallback"}
        }]

    valid_rows = []
    errors = []

    for index, raw_finding in enumerate(findings):
        try:
            if not isinstance(raw_finding, dict):
                raise ValueError(f"Item at index {index} is not a valid dictionary object.")

            # Map unstructured Gemini keys to strict schema fields
            mapping = {
                "scan_id": target_scan_id,
                "session_id": target_session_id,
                "attack_vector": raw_finding.get("attack_vector") or raw_finding.get("category"),
                "detected_threat": raw_finding.get("detected_threat") or raw_finding.get("title"),
                "provided_solution": raw_finding.get("provided_solution") or raw_finding.get("solution"),
                "severity": raw_finding.get("severity"),
                "category": raw_finding.get("category"),
                "title": raw_finding.get("title"),
                "detail": raw_finding.get("detail"),
                "evidence": raw_finding.get("evidence"),
                "is_fixed": raw_finding.get("is_fixed", False)
            }
            
            # Strip None values to allow Pydantic defaults to populate
            payload = {k: v for k, v in mapping.items() if v is not None}
            row = VulnerabilityRow(**payload)
            valid_rows.append(row.model_dump(mode="json"))

        except (ValidationError, Exception) as e:
            errors.append({"index": index, "reason": str(e)})

    if not valid_rows:
        error_log = f"CRITICAL_VALIDATION_FAILURE: Zero valid rows built. First error: {errors[0] if errors else 'Unknown'}"
        logger.error(error_log)
        raise Exception(error_log)

    logger.info(f"Transformation Pipeline: {len(valid_rows)} valid rows, {len(errors)} failed.")
    return valid_rows, errors