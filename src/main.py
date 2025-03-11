from typing import Annotated

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Header,
    UploadFile,
    status,
    Response,
)
import fitz
from presidio_analyzer import AnalyzerEngine

from settings import Settings


settings = Settings()  # type: ignore
app = FastAPI(
    debug=settings.DEBUG,
)


def check_authorization(
    authorization_token: Annotated[str, Header()],
) -> None:
    if authorization_token != settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization token is invalid.",
        )


def get_pii(usertext):
    analyzer = AnalyzerEngine()
    detected_pii = analyzer.analyze(text=usertext, language="en")
    return detected_pii


def get_generators(text):
    detected_pii = get_pii(text)
    for pii in detected_pii:
        pii_dict = pii.to_dict()
        pii_text = text[pii_dict["start"] : pii_dict["end"]]
        yield pii_text


@app.post("/")
async def anonymize_document(
    document: UploadFile,
    _is_client_authorized: Annotated[None, Depends(check_authorization)],
):
    doc = fitz.open(stream=await document.read())

    for page in doc:
        page.wrap_contents()
        words_list = page.get_text("words", flags=fitz.TEXT_INHIBIT_SPACES)
        text = ""
        for word in words_list:
            text += word[4] + " "
        for data in get_generators(text):
            areas = page.search_for(data)
            [page.add_redact_annot(area, fill=(0, 0, 0)) for area in areas]
        page.apply_redactions()

    return Response(content=doc.write(), media_type=document.content_type)
