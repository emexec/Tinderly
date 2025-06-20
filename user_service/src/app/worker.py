import requests
import logging
from celery import Celery
import redis
from .core.config import redis_url, settings, smtp_url # ssl_options

logger = logging.getLogger(__name__)

redis_client = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    password=settings.REDIS_PASSWORD,
    db=0,
    decode_responses=True,
    ssl_cert_reqs=None
)

def store_2fa_code_in_redis(email: str, code: str):
    redis_client.setex(f"2fa:{email}", 300, code)

def get_2fa_code_from_redis(email: str):
    return redis_client.get(f"2fa:{email}")

celery_app = Celery("celery_worker", broker=redis_url, backend=redis_url)

celery_app.conf.update(
    # broker_use_ssl=ssl_options,
    # redis_backend_use_ssl=ssl_options,
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    enable_utc=True,
    timezone='Europe/Moscow',
    broker_connection_retry_on_startup=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)

@celery_app.task(
    name="send_2fa_email",
    bind=True,
    max_retries=3,
    default_retry_delay=5
)
def send_email_2fa_scheduled(self, email: str, code: str):
    try:
        response = requests.post(
            smtp_url,
            json={
                "to": email,
                "subject": "Your 2FA Code",
                "body": f"Your 2FA code is: {code}"
            },
            timeout=10
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.warning(f"Request exception in send_2fa_email: {exc}")
        self.retry(exc=exc)
    except Exception as e:
        logger.error(f"Unexpected error in send_2fa_email: {e}")
        return None
