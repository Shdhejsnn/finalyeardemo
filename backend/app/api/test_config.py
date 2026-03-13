from fastapi import APIRouter
from app.core.config import settings

router = APIRouter()

@router.get("/config-test")
def config_test():
    """
    Test endpoint to confirm config loading
    """
    return {
        "app_name": settings.APP_NAME,
        "version": settings.API_VERSION,
        "debug": settings.DEBUG
    }