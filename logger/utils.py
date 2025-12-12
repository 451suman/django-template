import re

from django.conf import settings

SENSITIVE_KEYS = ["password", "token", "access", "refresh"]

# Exclude sensitive keys from `settings.py` instead of hardcoding it into logger
if hasattr(settings, "API_LOGGER_EXCLUDE_KEYS"):
    if type(settings.API_LOGGER_EXCLUDE_KEYS) in (list, tuple):
        SENSITIVE_KEYS.extend(settings.API_LOGGER_EXCLUDE_KEYS)


def get_header(request=None):
    regex = re.compile("^HTTP_")
    return dict(
        (regex.sub("", header), value)
        for (header, value) in request.META.items()
        if header.startswith("HTTP_")
    )


def is_api_logger_enabled():
    api_logger_db = False
    if hasattr(settings, "API_LOGGER_DB"):
        api_logger_db = settings.API_LOGGER_DB

    api_logger_signal = False
    if hasattr(settings, "API_LOGGER_SIGNAL"):
        api_logger_signal = settings.API_LOGGER_SIGNAL

    return api_logger_db or api_logger_signal


def get_client_ip(request):
    try:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
            return ip

        else:
            ip = request.META.get("REMOTE_ADDR")
            return ip

    except Exception as e:
        return "No IP for the user"


def db_log_enabled():
    api_logger_db = False
    if hasattr(settings, "API_LOGGER_DB"):
        api_logger_db = settings.API_LOGGER_DB
    return api_logger_db


def get_user(request):
    if hasattr(request, "user"):
        # If the user is authenticated, return the corresponding UserAccount instance
        if request.user.is_authenticated:
            return request.user  # Assuming request.user is an instance of UserAccount
        else:
            return None  # For unauthenticated users, return None
    return None


# NOTE: Yo chai chatgpt zindawaad ho, I don't understand regex :P


def mask_sensitive_data(data, mask_api_parameters=False):
    """
    Masks or removes sensitive data such as passwords or tokens from dictionaries or URL strings.

    Parameters:
    -----------
    data : dict, str, list
        The input data to be cleaned. Can be a dictionary, list of dicts, or URL string.
    mask_api_parameters : bool
        If True, applies masking to query parameters in a string (URL format).
        Otherwise, it recursively filters keys from dictionaries/lists.

    Returns:
    --------
    dict, str, list
        The sanitized version of the input data, with sensitive values replaced by "***FILTERED***".
    """
    if type(data) is not dict:
        # Handle query string case if enabled
        if mask_api_parameters and type(data) is str:
            for sensitive_key in SENSITIVE_KEYS:
                # Replaces values like token=abcd1234& -> token=***FILTERED***&
                data = re.sub(
                    "({}=)(.*?)($|&)".format(sensitive_key), r"\1***FILTERED***\3", data
                )

        # If it's a list, sanitize each item recursively
        if type(data) is list:
            data = [mask_sensitive_data(item) for item in data]
        return data

    # Process each key-value pair in the dictionary
    for key, value in data.items():
        if key in SENSITIVE_KEYS:
            data[key] = "***FILTERED***"  # Mask sensitive keys

        elif type(value) is dict:
            data[key] = mask_sensitive_data(data[key])  # Recurse into nested dict

        elif type(value) is list:
            data[key] = [
                mask_sensitive_data(item) for item in data[key]
            ]  # Recurse into list

    return data
