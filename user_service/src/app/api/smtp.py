from fastapi import APIRouter, HTTPException
import smtplib
from email.message import EmailMessage

from ..schemas.schemas import EmailRequest
from ..core.config import settings

smtp_router = APIRouter(prefix="/smtp")


@smtp_router.post("/send-email/2-fa")
def send_email(data: EmailRequest):
    msg = EmailMessage()
    msg["From"] = settings.SMTP_USER
    msg["To"] = data.to
    msg["Subject"] = data.subject
    msg.set_content(data.body)

    try:
        with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
            server.send_message(msg)
        return {"detail": "Email sent"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {e}")
