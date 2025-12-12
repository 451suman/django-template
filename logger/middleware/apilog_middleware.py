from datetime import datetime
import importlib
import json
import re
import sys
import time
import uuid
from django.conf import settings
from django.urls import resolve
from django.utils import timezone
from logger.apps import LOGGER_THREAD
from logger.utils import get_client_ip, get_header, mask_sensitive_data, get_user
from logger import API_LOGGER_SIGNAL
from django.contrib.auth import get_user_model

User = get_user_model()


class APILoggerMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

        self.API_LOGGER_DB = False
        if hasattr(settings, "API_LOGGER_DB"):
            self.API_LOGGER_DB = settings.API_LOGGER_DB

        self.API_LOGGER_SKIP_RESPONSE_BODY = []
        if hasattr(settings, "API_LOGGER_SKIP_RESPONSE_BODY"):
            self.API_LOGGER_SKIP_RESPONSE_BODY = settings.API_LOGGER_SKIP_RESPONSE_BODY

        self.API_LOGGER_PATH_TYPE = "ABSOLUTE"
        if hasattr(settings, "API_LOGGER_PATH_TYPE"):
            if self.API_LOGGER_PATH_TYPE in ["ABSOLUTE", "RAW_URI", "FULL_PATH"]:
                self.API_LOGGER_PATH_TYPE = self.API_LOGGER_PATH_TYPE

        self.API_LOGGER_SKIP_URL_NAME = []
        if hasattr(settings, "API_LOGGER_SKIP_URL_NAME"):
            if type(settings.API_LOGGER_SKIP_URL_NAME) is tuple or list:
                self.API_LOGGER_SKIP_URL_NAME = settings.API_LOGGER_SKIP_URL_NAME

        self.API_LOGGER_SKIP_NAMESPACE = []
        if hasattr(settings, "API_LOGGER_SKIP_NAMESPACE"):
            if type(settings.API_LOGGER_SKIP_NAMESPACE) is tuple or list:
                self.API_LOGGER_SKIP_NAMESPACE = settings.API_LOGGER_SKIP_NAMESPACE

        self.API_LOGGER_METHODS = []
        if hasattr(settings, "API_LOGGER_METHODS"):
            if type(settings.API_LOGGER_METHODS) is tuple or list:
                self.API_LOGGER_METHODS = settings.API_LOGGER_METHODS

        self.API_LOGGER_STATUS_CODE = [
            100,
            101,
            102,
            103,  # 1xx: Informational
            200,
            201,
            202,
            203,
            204,
            205,
            206,
            207,
            208,
            226,  # 2xx: Success
            300,
            301,
            302,
            303,
            304,
            305,
            306,
            307,
            308,  # 3xx: Redirection
            400,
            401,
            402,
            403,
            404,
            405,
            406,
            407,
            408,
            409,
            410,
            411,
            412,
            413,
            414,
            415,
            416,
            417,
            418,
            421,
            422,
            423,
            424,
            425,
            426,
            427,
            428,
            429,
            431,
            451,  # 4xx: Client Error
            500,
            501,
            502,
            503,
            504,
            505,
            506,
            507,
            508,
            510,
            511,  # 5xx: Server Error
        ]
        if hasattr(settings, "API_LOGGER_STATUS_CODE"):
            if type(settings.API_LOGGER_STATUS_CODE) is list or tuple:
                self.API_LOGGER_STATUS_CODE = settings.API_LOGGER_STATUS_CODE

        self.API_LOGGER_ENABLE_TRACING = False
        self.API_LOGGER_TRACING_ID_HEADER_NAME = None
        if hasattr(settings, "API_LOGGER_ENABLE_TRACING"):
            self.API_LOGGER_ENABLE_TRACING = settings.API_LOGGER_ENABLE_TRACING
            if self.API_LOGGER_ENABLE_TRACING and hasattr(
                settings, "API_LOGGER_TRACING_ID_HEADER_NAME"
            ):
                self.API_LOGGER_TRACING_ID_HEADER_NAME = (
                    settings.API_LOGGER_TRACING_ID_HEADER_NAME
                )

        self.tracing_func_name = None
        if hasattr(settings, "API_LOGGER_TRACING_FUNC"):
            mod_name, func_name = settings.API_LOGGER_TRACING_FUNC.rsplit(".", 1)
            mod = importlib.import_module(mod_name)
            self.tracing_func_name = getattr(mod, func_name)

        self.API_LOGGER_MAX_REQUEST_BODY_SIZE = -1
        if hasattr(settings, "API_LOGGER_MAX_REQUEST_BODY_SIZE"):
            if type(settings.API_LOGGER_MAX_REQUEST_BODY_SIZE) is int:
                self.API_LOGGER_MAX_REQUEST_BODY_SIZE = (
                    settings.API_LOGGER_MAX_REQUEST_BODY_SIZE
                )

        self.API_LOGGER_MAX_RESPONSE_BODY_SIZE = -1
        if hasattr(settings, "API_LOGGER_MAX_RESPONSE_BODY_SIZE"):
            if type(settings.API_LOGGER_MAX_RESPONSE_BODY_SIZE) is int:
                self.API_LOGGER_MAX_RESPONSE_BODY_SIZE = (
                    settings.API_LOGGER_MAX_RESPONSE_BODY_SIZE
                )

    def is_static_or_media_request(self, path):
        static_url = getattr(settings, "STATIC_URL", None)
        media_url = getattr(settings, "MEDIA_URL", None)

        if static_url and static_url != "/" and path.startswith(static_url):
            return True

        if media_url and media_url != "/" and path.startswith(media_url):
            return True

    def __call__(self, request):
        if self.is_static_or_media_request(request.path):
            return self.get_response(request)

        if self.API_LOGGER_DB:
            url_name = resolve(request.path_info).url_name
            namespace = resolve(request.path_info).namespace

            if namespace == "admin":
                return self.get_response(request)

            if url_name in self.API_LOGGER_SKIP_URL_NAME:
                return self.get_response(request)

            if namespace in self.API_LOGGER_SKIP_NAMESPACE:
                return self.get_response(request)

            # For each request/response cycle after view is called, code below runs (hopefully)

            start_time = time.time()
            headers = get_header(request=request)
            method = request.method

            request_data = ""
            try:
                request_data = json.loads(request.body) if request.body else ""
                if self.API_LOGGER_MAX_REQUEST_BODY_SIZE > -1:
                    if sys.getsizeof(request) > self.API_LOGGER_MAX_RESPONSE_BODY_SIZE:
                        """Ignore request if body size is greater than specified size"""

                        request_data = ""

            except Exception:
                pass

            tracing_id = None
            if self.API_LOGGER_ENABLE_TRACING:
                if self.API_LOGGER_TRACING_ID_HEADER_NAME:
                    tracing_id = headers.get(self.API_LOGGER_TRACING_ID_HEADER_NAME)

                if not tracing_id:
                    """
                    If tracing ID is not present in header, get it from tracing function
                    """

                    if self.tracing_func_name:
                        tracing_id = self.tracing_func_name

                    else:
                        tracing_id = str(uuid.uuid4())

                request.tracing_id = tracing_id

            # Code to run before view and later middleware is called

            # Log registerd status code
            response = self.get_response(request)
            if (
                self.API_LOGGER_STATUS_CODE
                and response.status_code not in self.API_LOGGER_STATUS_CODE
            ):
                return response

            if (
                len(self.API_LOGGER_METHODS) > 0
                and method not in self.API_LOGGER_METHODS
            ):
                return response

            self.API_LOGGER_CONTENT_TYPES = [
                "application/json",
                "application/vnd.api+json",
                "application/gzip",
                "application/octet-stream",
                "text/calendar",
            ]
            if hasattr(settings, "API_LOGGER_CONTENT_TYPES") and type(
                settings.API_LOGGER_CONTENT_TYPES
            ) in (list, tuple):
                for content_type in settings.API_LOGGER_CONTENT_TYPES:
                    if re.match(r"^application\/vnd\..+\+json$", content_type):
                        self.API_LOGGER_CONTENT_TYPES.append(content_type)

            if response.get("content-type") in self.API_LOGGER_CONTENT_TYPES:
                if response.get("content-type") == "application/gzip":
                    response_body = "** GZIP Archive **"
                elif response.get("content-type") == "application/octet-stream":
                    response_body = "** Binary File **"
                elif getattr(response, "streaming", False):
                    response_body = "** Streaming **"
                elif response.get("content-type") == "text/calendar":
                    response_body = "** Calendar **"

                else:
                    if type(response.content) is bytes:
                        response_body = json.loads(response.content.decode())
                    else:
                        response_body = json.loads(response.content)
                if self.API_LOGGER_MAX_RESPONSE_BODY_SIZE > -1:
                    if (
                        sys.getsizeof(response_body)
                        > self.API_LOGGER_MAX_RESPONSE_BODY_SIZE
                    ):
                        response_body = ""
                if self.API_LOGGER_PATH_TYPE == "ABSOLUTE":
                    api = request.build_absolute_uri()
                elif self.API_LOGGER_PATH_TYPE == "FULL_PATH":
                    api = request.get_full_path()
                elif self.API_LOGGER_PATH_TYPE == "RAW_URI":
                    api = request.get_raw_uri()
                else:
                    api = request.build_absolute_uri()

                # Get the current time in a timezone-aware manner
                if settings.USE_TZ:
                    # When USE_TZ is True, use timezone-aware datetime
                    current_time = timezone.now()
                else:
                    # When USE_TZ is False, use naive datetime
                    current_time = datetime.now()

                data = dict(
                    api=mask_sensitive_data(api, mask_api_parameters=True),
                    headers=mask_sensitive_data(headers),
                    body=mask_sensitive_data(request_data),
                    method=method,
                    client_ip_address=get_client_ip(request),
                    response=mask_sensitive_data(response_body),
                    status_code=response.status_code,
                    execution_time=time.time() - start_time,
                    added_on=current_time,
                    user=get_user(request),
                )
                if self.API_LOGGER_DB and LOGGER_THREAD:
                    d = data.copy()
                    d["headers"] = (
                        json.dumps(d["headers"], indent=4, ensure_ascii=False)
                        if d.get("headers")
                        else ""
                    )
                    if request_data:
                        d["body"] = (
                            json.dumps(d["body"], indent=4, ensure_ascii=False)
                            if d.get("body")
                            else ""
                        )
                    d["response"] = (
                        json.dumps(d["response"], indent=4, ensure_ascii=False)
                        if d.get("response")
                        else ""
                    )
                    if url_name in self.API_LOGGER_SKIP_RESPONSE_BODY:
                        d["response"] = (
                            "*** Response body skipped to not overload DB ***"
                        )
                    LOGGER_THREAD.put_log_data(data=d)
                if API_LOGGER_SIGNAL:
                    if tracing_id:
                        data.update({"tracing_id": tracing_id})
                    API_LOGGER_SIGNAL.listen(**data)
            else:
                return response
        else:
            response = self.get_response(request)
        return response
