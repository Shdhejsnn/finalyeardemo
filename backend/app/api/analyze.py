from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.models.url_request import URLRequest
from app.models.url_response import URLResponse

from app.services.analysis_service import AnalysisService
from app.services.log_service import LogService

from app.core.dependencies import get_db


router = APIRouter()

analysis_service = AnalysisService()
log_service = LogService()


@router.post("/analyze-url", response_model=URLResponse)
def analyze_url(request: URLRequest, db: Session = Depends(get_db)):

    url = str(request.url)

    result = analysis_service.analyze_url(
        url,
        form_detected=request.form_detected,
        page_flags=request.page_flags,
    )

    log_service.log_event(
        db,
        url,
        result,
        source=request.source,
        form_detected=request.form_detected,
    )

    return result
