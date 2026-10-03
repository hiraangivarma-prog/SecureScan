from typing import Literal
from pydantic import BaseModel


Severity = Literal["Informational", "Low", "Medium", "High", "Critical"]
Confidence = Literal["Low", "Medium", "High"]


class Finding(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    evidence: str
    description: str
    impact: str
    recommendation: str
