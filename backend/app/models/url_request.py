from pydantic import BaseModel, HttpUrl


class URLRequest(BaseModel):
    """
    Request schema for URL analysis.
    """

    url: HttpUrl
    form_detected: bool = False
    source: str = "extension"
    page_flags: list[str] = []
