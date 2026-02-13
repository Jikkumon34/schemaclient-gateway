"""
Django settings for gateway project.
"""

from django.core.exceptions import ImproperlyConfigured
import os
from pathlib import Path
from datetime import timedelta

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent
DEV_SECRET_KEY = "django-insecure-dev-only-change-me"


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_csv(name: str, default: list[str] | None = None) -> list[str]:
    raw = os.getenv(name)
    if raw is None:
        return list(default or [])
    return [item.strip() for item in raw.split(",") if item.strip()]


def _sqlite_db_path() -> str:
    raw = os.getenv("DJANGO_SQLITE_PATH", "db.sqlite3").strip() or "db.sqlite3"
    db_path = Path(raw).expanduser()
    if not db_path.is_absolute():
        db_path = BASE_DIR / db_path
    return str(db_path)


DJANGO_ENV = os.getenv("DJANGO_ENV", "development").strip().lower()
IS_PRODUCTION = DJANGO_ENV == "production"


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv(
    "DJANGO_SECRET_KEY",
    DEV_SECRET_KEY,
)
if IS_PRODUCTION and SECRET_KEY == DEV_SECRET_KEY:
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set for production.")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = _env_bool("DJANGO_DEBUG", not IS_PRODUCTION)

ALLOWED_HOSTS = _env_csv(
    "DJANGO_ALLOWED_HOSTS",
    ["127.0.0.1", "localhost"] if DEBUG else [],
)
if IS_PRODUCTION and not ALLOWED_HOSTS:
    raise ImproperlyConfigured("DJANGO_ALLOWED_HOSTS must be set for production.")

CSRF_TRUSTED_ORIGINS = _env_csv("DJANGO_CSRF_TRUSTED_ORIGINS")


# Application definition

INSTALLED_APPS = [
    "channels",
    "accounts",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "tunnel",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "tunnel.middleware.TunnelSubdomainMiddleware",
]

ROOT_URLCONF = "gateway.urls"
ASGI_APPLICATION = "gateway.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "gateway.wsgi.application"


# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": _sqlite_db_path(),
        "OPTIONS": {
            "timeout": _env_int("DJANGO_SQLITE_TIMEOUT_SECONDS", 30),
        },
    }
}
DATABASES["default"]["CONN_MAX_AGE"] = _env_int("DJANGO_DB_CONN_MAX_AGE", 60 if IS_PRODUCTION else 0)


# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = []

# Proxy + secure cookie defaults for EC2 behind Nginx/Cloudflare.
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

if not DEBUG:
    SESSION_COOKIE_SECURE = _env_bool("DJANGO_SESSION_COOKIE_SECURE", True)
    CSRF_COOKIE_SECURE = _env_bool("DJANGO_CSRF_COOKIE_SECURE", True)
    SECURE_SSL_REDIRECT = _env_bool("DJANGO_SECURE_SSL_REDIRECT", True)
    SECURE_HSTS_SECONDS = _env_int("DJANGO_SECURE_HSTS_SECONDS", 31536000)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = _env_bool("DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS", True)
    SECURE_HSTS_PRELOAD = _env_bool("DJANGO_SECURE_HSTS_PRELOAD", False)
    SECURE_REFERRER_POLICY = os.getenv("DJANGO_SECURE_REFERRER_POLICY", "same-origin")
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = "DENY"

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "accounts.User"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=_env_int("JWT_ACCESS_TOKEN_MINUTES", 30)),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=_env_int("JWT_REFRESH_TOKEN_DAYS", 14)),
    "UPDATE_LAST_LOGIN": True,
}

DESKTOP_AUTH_CODE_TTL_SECONDS = _env_int("DESKTOP_AUTH_CODE_TTL_SECONDS", 180)

# Tunnel gateway settings
TUNNEL_BASE_DOMAIN = os.getenv("TUNNEL_BASE_DOMAIN", "mysmeclabs.com")
TUNNEL_PUBLIC_SCHEME = os.getenv("TUNNEL_PUBLIC_SCHEME", "https")
TUNNEL_REQUEST_TIMEOUT_SECONDS = _env_int("TUNNEL_REQUEST_TIMEOUT_SECONDS", 40)
TUNNEL_HEARTBEAT_TTL_SECONDS = _env_int("TUNNEL_HEARTBEAT_TTL_SECONDS", 120)
TUNNEL_MAX_REQUEST_BODY_BYTES = _env_int("TUNNEL_MAX_REQUEST_BODY_BYTES", 5 * 1024 * 1024)
TUNNEL_DB_POLL_INTERVAL_MS = _env_int("TUNNEL_DB_POLL_INTERVAL_MS", 120)

CHANNEL_REDIS_URL = os.getenv("CHANNEL_REDIS_URL", "").strip()
if CHANNEL_REDIS_URL:
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            "CONFIG": {"hosts": [CHANNEL_REDIS_URL]},
        }
    }
else:
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels.layers.InMemoryChannelLayer",
        }
    }
