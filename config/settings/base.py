import os
import platform
from pathlib import Path

from corsheaders.defaults import default_headers
from dotenv import load_dotenv

from logger.utils import SENSITIVE_KEYS


def load_env(os_name):
    """Loads environment variables based on the operating system using suitable methods.

    Args:
        os_name: The name of the operating system (e.g., 'linux', 'windows', 'darwin').

    Raises:
        ValueError: If the provided OS name is not supported.
    """
    if os_name in ("linux", "darwin"):
        # Assuming a `.env` file for Linux and macOS
        load_dotenv()
    elif os_name == "windows":
        # Assuming a `.env` file for Windows
        load_dotenv(dotenv_path=os.path.join(os.environ["SYSTEMROOT"], ".env"))
    else:
        raise ValueError(f"Unsupported operating system: {os_name}")


# Get the operating system name
os_name = platform.system().lower()

# Load environment variables based on OS
load_env(os_name)

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent

SECRET_KEY = os.getenv("SECRET_KEY", "your-default-secret-key")

INSTALLED_APPS = [
    # Default Django apps
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    # Third-party apps
    "django_summernote",
    "rest_framework",  # Django REST framework
    "rest_framework_simplejwt",  # JWT auth for DRF
    "rest_framework_simplejwt.token_blacklist",
    "account",
    "logger",
]


MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "logger.middleware.apilog_middleware.APILoggerMiddleware",
]



ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"


# Password validation
AUTH_PASSWORD_VALIDATORS = [
    # Add password validators here
]

# Internationalization
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

AUTH_USER_MODEL = "account.UserAccount"

LOG_DIR = os.path.join(BASE_DIR, "logs")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] [{levelname}] {message} ({filename}:{lineno})",
            "style": "{",
        },
        "simple": {
            "format": "[{levelname}] {message}",
            "style": "{",
        },
    },
    "handlers": {
        "file": {
            "level": "DEBUG",
            "class": "logging.handlers.WatchedFileHandler",
            "filename": os.path.join(LOG_DIR, "django.log"),
            "formatter": "verbose",
        },
        "console": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "simple",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["file", "console"],
            "level": "DEBUG",
            "propagate": True,
        },
        "apps": {  # Custom apps logger
            "handlers": ["file", "console"],
            "level": "DEBUG",
            "propagate": True,
        },
    },
}

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
}

MYPAY_GATEWAY_URL = os.environ.get("MYPAY_GATEWAY_URL")

QR_DATA = {
    "pointOfInitialization": os.environ.get("POINT_OF_INITIALIZATION"),
    "acquirerId": os.environ.get("ACQUIRER_ID"),
    "merchantId": os.environ.get("MERCHANT_ID"),
    "merchantName": os.environ.get("MERCHANT_NAME"),
    "merchantCategoryCode": os.environ.get("MERCHANT_CATEGORY_CODE"),
    "merchantCountry": os.environ.get("MERCHANT_COUNTRY"),
    "merchantCity": os.environ.get("MERCHANT_CITY"),
    "merchantPostalCode": os.environ.get("MERCHANT_POSTAL_CODE"),
    "merchantLanguage": os.environ.get("MERCHANT_LANGUAGE"),
    "transactionCurrency": os.environ.get("TRANSACTION_CURRENCY"),
    "valueOfConvenienceFeeFixed": os.environ.get("VALUE_OF_CONVENIENCE_FEE_FIXED"),
    "referenceLabel": os.environ.get("REFERENCE_LABEL"),
    "mobileNo": os.environ.get("MOBILE_NO"),
    "storeLabel": os.environ.get("STORE_LABEL"),
    "terminalLabel": os.environ.get("TERMINAL_LABEL"),
    "purposeOfTransaction": os.environ.get("QR_PURPOSE_OF_TRANSACTION"),
    "additionalConsumerDataRequest": os.environ.get("ADDITIONAL_CONSUMER_DATA_REQUEST"),
    "loyaltyNumber": os.environ.get("LOYALTY_NUMBER"),
    "USER_ID": os.environ.get("NEPALPAY_API_USERNAME"),
    # "token":os.environ.get("QR_TOKEN"),
}

BASE_URL = "http://localhost:8002"

CORS_ALLOW_HEADERS = list(default_headers) + [
    "Authorization",
    "Content-Type",
    "Timestamp",
    "Signature",
]

### IMPORTANT ####
## The option below is really necessay for logger to work
API_LOGGER_DB = True  # Use DB for writing logs, this initializes/activates the logger
LOGGER_WRITE_INTERVAL = (
    5  # Interval to bulk write into DB to not flood/self ddos it (?)
)
LOGGER_MAX_QUEUE_SIZE = 5  # Max queue size before writing into database
RUN_LOGGER = "true"


# Some nice options to make logger use in other project to I hope
API_LOGGER_PATH_TYPE = "ABSOLUTE"  # Possible ["ABSOLUTE", "RAW_URI", "FULL_PATH"]
API_LOGGER_SKIP_URL_NAME = []
SENSITIVE_KEYS = [
    "AUTHORIZATION"
]  # NOTE : Add sensitive filed here instead of hardcoding ti to logger
API_LOGGER_SKIP_NAMESPACE = []  # Skip apps in the list
API_LOGGER_SKIP_RESPONSE_BODY = [
    "apilog_list",
    "apilog_detail",
]  # Skip response body for stuff
API_LOGGER_METHODS = ["PUT", "PATCH", "GET", "POST", "DELETE", "CONNECT", "HEAD"]
API_LOGGER_MAX_REQUEST_BODY_SIZE = 1048576  # 1MB
API_LOGGER_MAX_RESPONSE_BODY_SIZE = 1048576

# Audit log test
AUDITLOG_INCLUDE_ALL_MODELS = True
AUDITLOG_MASK_TRACKING_FIELDS = ("password", "api_key", "secret_token")
AUDITLOG_EXCLUDE_TRACKING_MODELS = ("ApiLogModel",)
