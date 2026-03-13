from pydantic import BaseModel, Field


class URLResponse(BaseModel):
    """
    Response returned after threat analysis.
    """

    decision: str
    risk_score: float
    severity: int
    summary: str
    reasons: list[str] = Field(default_factory=list)
    captcha_required: bool = False
