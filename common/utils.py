import base64
import hashlib
import hmac
import io
import os
import random
import secrets
import string
import uuid
import logging
import qrcode
import requests
from datetime import datetime
from decimal import Decimal
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.mail import EmailMultiAlternatives
from django.db.models import F, Q
from django.template.loader import render_to_string
from django.utils.text import slugify
from django.core.validators import RegexValidator
from rest_framework import serializers
from rest_framework.fields import ImageField
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

logger = logging.getLogger("django")


phone_validator = RegexValidator(
    regex=r"^9\d{9}$", message="Phone number must be 10 digits long and start with 9."
)


def validate_phone_number(phone_number):
    try:
        phone_validator(phone_number)
        return True  # Valid phone number
    except ValidationError as e:
        print(e)  # or handle the error as you like
        return False  # Invalid phone number


class GenerateKey:
    @staticmethod
    def return_value():
        key = str(random.randint(100000, 999999))
        return key


def generate_unique_id():
    return str(uuid.uuid4())


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def send_verification_email(email, otp):
    email_template = render_to_string(
        "../templates/signup_otp.html", {"otp": otp, "username": email}
    )
    sign_up = EmailMultiAlternatives(
        "Otp Verification",
        "Otp Verification",
        settings.EMAIL_HOST_USER,
        [email],
    )
    sign_up.attach_alternative(email_template, "text/html")
    sign_up.send()


def send_activation_success_email(user_email):
    # Rendering the email template
    email_template = render_to_string("signup_success.html", {"username": user_email})

    # Creating and sending the email
    sign_up = EmailMultiAlternatives(
        "Account successfully activated",
        "Account successfully activated",
        settings.EMAIL_HOST,
        [user_email],
    )
    sign_up.attach_alternative(email_template, "text/html")
    sign_up.send()


# Reusable image upload path generator
def profile_image_upload_path(instance, filename):
    ext = filename.split(".")[-1]
    short_uuid = str(uuid.uuid4())[:8]
    new_filename = f"{short_uuid}.{ext}"
    model_name = instance.__class__.__name__.lower()
    return os.path.join(model_name, "profile", new_filename)


def image_upload_path(instance, filename):
    ext = filename.split(".")[-1]
    short_uuid = str(uuid.uuid4())[:8]
    new_filename = f"{short_uuid}.{ext}"
    model_name = instance.__class__.__name__.lower()
    return os.path.join(model_name, new_filename)


def pan_document_upload_path(instance, filename):
    ext = filename.split(".")[-1]
    short_uuid = str(uuid.uuid4())[:8]
    new_filename = f"{short_uuid}.{ext}"
    model_name = instance.__class__.__name__.lower()
    return os.path.join(model_name, "pan", new_filename)


def validate_mobile_no(value):
    if not value.isdigit():
        raise ValidationError("Mobile number must contain only digits.")

    if len(value) != 10:
        raise ValidationError("Mobile number must be 10 digits long.")

    # Additional checks can be added here, such as verifying the prefix (e.g., country code)
    if not value.startswith("9"):
        raise ValidationError("Mobile number should start with 9.")


def generate_secret_key(length=50):
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(chars) for _ in range(length))


def generate_unique_ref(code):
    """
    Generate a unique booking reference using UUID4.
    Format: BK-<YYYYMMDD>-<first10chars of uuid4>
    """
    token = uuid.uuid4().hex[:6].upper()
    return f"{code}-{token}"


# Mypay payment initialize
def initiate_mypay_payment(**data):
    url = os.environ.get("MYPAY_GATEWAY_URL")

    headers = {"API_KEY": os.environ.get("API_KEY"), "Content-Type": "application/json"}

    amount = data.get("amount")
    if isinstance(amount, Decimal):
        amount = float(amount)

    data = {
        "OrderId": data.get("unique_ref_no"),
        "Amount": amount,
        "UserName": os.environ.get("MYPAY_USERNAME"),
        "Password": os.environ.get("MYPAY_PASSWORD"),
        "MerchantId": os.environ.get("MYPAY_MERCHANTID"),
        "ReturnUrl": os.environ.get("ReturnUrl"),
    }
    print(data)

    response = requests.post(url=url, headers=headers, json=data)
    json_reposne = response.json()
    return json_reposne


# generate unique bill number
def generate_bill_number(length):
    """
    Generates a bill number of the specified length using characters from "shreeommandir".

    Args:
        length (int): The desired length of the bill number.

    Returns:
        str: The generated bill number.
    """
    # Characters from "shreeommandir"
    characters = "SHREOMANDI"

    # Generate bill number
    bill_number = "".join(random.choice(characters) for _ in range(length))

    return bill_number


# sign data for nepal pay
def sign_data(message, private_key):
    print(type(private_key))
    key = RSA.importKey(str(private_key))

    h = SHA256.new(message.encode("utf-8"))
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(h)

    print("signature...................")
    print(base64.b64encode(signature).decode("utf-8"))
    return base64.b64encode(signature).decode("utf-8")


# nchl dynamic qr code
def generate_qr_code(order_amount):
    api_url = os.environ.get("NCHL_API_URL")

    QR_DATA = settings.QR_DATA
    QR_DATA["pointOfInitialization"] = 12
    QR_DATA["transactionAmount"] = str(order_amount)

    username = os.environ.get("NEPALPAY_USERNAME")
    password = os.environ.get("NEPALPAY_PASSWORD")

    combined = f"{username}:{password}"

    base64_encoded = base64.b64encode(combined.encode("utf-8")).decode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": "Basic " + base64_encoded,
    }

    PRIVATE_KEY_STRING = os.environ.get("NCHL_PRIVATE_KEY_STRING")

    # if PRIVATE_KEY_STRING is None:
    #     PRIVATE_KEY_STRING = "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQC009W2gk4oo7x9drPF8EAGBX8kba4LwnLqPYfh8im8nK5nt/hE\nvFiAgzCUfAoW4iNMH6zg/q3nhvqhaca9YKrXZpFlqsxZnxR2XOZzJdMHXrenK1N5\nKygKxKlJx6VEOUtC23GwzNsrMeXKzAp2/+9lFnPwoticn+aFcY59Ke49qwIDAQAB\nAoGBALB+KhOu71ZfKfRTTXge3H6EEuqdWskDi2HxmJUB5ZbAXsHBIEMGimM0qM/k\nmXxoUAdWy0f3jAl1B19QfLgOh+94kvPZWyVivTONctlWTKANhTR9veRyl5p72yZh\niYqHMArVqlve4EpbmpOa6cGwTG0kJylQCaR0IbjVX23uYq5xAkEA+y+uzCigQa/5\n4GKOyc1jihdlVezNfE/P24yu6ahoIHNFTdReBtKFBSIusrYAURWzXYEyzxnVVgBd\nhsxonOUVrQJBALhK+Pm+97PP5OhCQxPCgcOOT8Pk68NZ8VZxeyjYBBNLYz2JBLYO\ngNfsXNHCKt/gPnNuGODyy8/dkk4fMk+8m7cCQQCmu1n97qGhuJvW09UQIyOFkE4V\noSAs+hVxGIsqUjz7/Ufth5/6S1c8txnkSmcfa5Yp5Q7C5dT0Rz3NsnVmX7HpAkBY\njdXzE7sskNHadLSMkyMNV52mcKKE/PwFYIQgjSPwLYJjOCqmXHO2zWGQfS9i4frA\nNoAH30Ll//7kQQNI40UjAkBhkIPAyA+p9OcFSD2OyICWpOXCQmUsyFhrGW2S67A6\nzyAA58sTfW5gqXcLGoqlf8DNY9tdghdVkUBOHnhA+e2j\n-----END RSA PRIVATE KEY-----"

    transaction_currency = QR_DATA["transactionCurrency"]

    acquirer_id = os.environ.get("ACQUIRER_ID")
    merchant_id = os.environ.get("MERCHANT_ID")
    merchant_category_code = os.environ.get("MERCHANT_CATEGORY_CODE")
    transaction_currency = "524"
    transaction_amount = str(order_amount)
    bill_number = generate_bill_number(14)
    user_id = os.environ.get("NEPALPAY_API_USERNAME")

    message = ",".join(
        [
            acquirer_id,
            merchant_id,
            merchant_category_code,
            transaction_currency,
            transaction_amount,
            bill_number,
            user_id,
        ]
    )

    token = sign_data(message, PRIVATE_KEY_STRING)

    print(token, "token")

    QR_DATA["token"] = token

    QR_DATA["billNumber"] = bill_number

    try:

        print("headers", headers)
        print("payload", QR_DATA)

        logger.info(f"headers: {headers}")
        logger.info(f"payload: {QR_DATA}")

        response = requests.post(api_url, headers=headers, json=QR_DATA)

        logger.info(f"Response: {response.status_code} - {response.text}")

        print(response, "Response")

        response.raise_for_status()  # Raise an exception for HTTP errors
        return response.json()  # Return the JSON response
    except Exception as e:
        logger.error(f"Something went wrong: {e}", exc_info=True)
        print("something went wrong")


# nchl static qr code
def generate_static_qr_code(store, terminal):
    api_url = os.environ.get("NCHL_API_URL")

    QR_DATA = settings.QR_DATA
    QR_DATA["pointOfInitialization"] = 11
    QR_DATA["transactionAmount"] = "0.00"
    # QR_DATA["storeLabel"] = store
    QR_DATA["terminalLabel"] = terminal

    username = os.environ.get("NEPALPAY_USERNAME")
    password = os.environ.get("NEPALPAY_PASSWORD")

    combined = f"{username}:{password}"

    base64_encoded = base64.b64encode(combined.encode("utf-8")).decode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": "Basic " + base64_encoded,
    }

    PRIVATE_KEY_STRING = os.environ.get("NCHL_PRIVATE_KEY_STRING")

    if PRIVATE_KEY_STRING is None:
        PRIVATE_KEY_STRING = "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQC009W2gk4oo7x9drPF8EAGBX8kba4LwnLqPYfh8im8nK5nt/hE\nvFiAgzCUfAoW4iNMH6zg/q3nhvqhaca9YKrXZpFlqsxZnxR2XOZzJdMHXrenK1N5\nKygKxKlJx6VEOUtC23GwzNsrMeXKzAp2/+9lFnPwoticn+aFcY59Ke49qwIDAQAB\nAoGBALB+KhOu71ZfKfRTTXge3H6EEuqdWskDi2HxmJUB5ZbAXsHBIEMGimM0qM/k\nmXxoUAdWy0f3jAl1B19QfLgOh+94kvPZWyVivTONctlWTKANhTR9veRyl5p72yZh\niYqHMArVqlve4EpbmpOa6cGwTG0kJylQCaR0IbjVX23uYq5xAkEA+y+uzCigQa/5\n4GKOyc1jihdlVezNfE/P24yu6ahoIHNFTdReBtKFBSIusrYAURWzXYEyzxnVVgBd\nhsxonOUVrQJBALhK+Pm+97PP5OhCQxPCgcOOT8Pk68NZ8VZxeyjYBBNLYz2JBLYO\ngNfsXNHCKt/gPnNuGODyy8/dkk4fMk+8m7cCQQCmu1n97qGhuJvW09UQIyOFkE4V\noSAs+hVxGIsqUjz7/Ufth5/6S1c8txnkSmcfa5Yp5Q7C5dT0Rz3NsnVmX7HpAkBY\njdXzE7sskNHadLSMkyMNV52mcKKE/PwFYIQgjSPwLYJjOCqmXHO2zWGQfS9i4frA\nNoAH30Ll//7kQQNI40UjAkBhkIPAyA+p9OcFSD2OyICWpOXCQmUsyFhrGW2S67A6\nzyAA58sTfW5gqXcLGoqlf8DNY9tdghdVkUBOHnhA+e2j\n-----END RSA PRIVATE KEY-----"

    transaction_currency = QR_DATA["transactionCurrency"]
    acquirer_id = os.environ.get("ACQUIRER_ID")
    merchant_id = os.environ.get("MERCHANT_ID")
    merchant_category_code = os.environ.get("MERCHANT_CATEGORY_CODE")
    transaction_currency = "524"
    transaction_amount = "0.00"
    bill_number = generate_bill_number(14)
    user_id = os.environ.get("NEPALPAY_API_USERNAME")

    message = ",".join(
        [
            acquirer_id,
            merchant_id,
            merchant_category_code,
            transaction_currency,
            bill_number,
            user_id,
        ]
    )

    token = sign_data(message, PRIVATE_KEY_STRING)
    print(token, "token")

    QR_DATA["token"] = token
    QR_DATA["billNumber"] = bill_number

    try:
        response = requests.post(api_url, headers=headers, json=QR_DATA)
        response.raise_for_status()
        return True, response.json()
    except Exception:
        print("something went wrong")
        return False, None


# fonepay token generate
def generate_hmac_sha512_token(data: str) -> str:
    secret_key = os.environ.get("FonePay_SecretKey")

    key = secret_key.encode()  # Encoding the secret key to bytes

    message = data.encode()  # Encode data to bytes

    # Generate HMAC-SHA512 hash
    hmac_hash = hmac.new(key, message, hashlib.sha512)

    # Convert the digest to hex string
    token = hmac_hash.hexdigest()

    return token


# https://ots.f1soft.com.np/secret/d8e4a2dc96b18bf6b954b50fd6c652fc?authCode=YzQ5MWQ4MzhhNDM1ODJkMDc0NTY0ZTg5ZmE5NTQ4ZmE%3D
# hGi7JPtXnRTxOefYFaQM6wUOky_7MceNsOsB8nhIus9rCBhuRgDI394wI7Y3injzKCM


# def prepare_ticket(QrcodeTicket, event_name, email, contact_no, booking_ticket_id):
#     # Ticket number
#     ticket_number = generate_ticket_number()

#     # QR payload
#     event_name = event_name
#     email = email
#     contact = contact_no
#     payload = f"{event_name}|{ticket_number}|{email}|{contact}"

#     # Generate QR
#     qr = qrcode.QRCode(
#         version=1,
#         error_correction=qrcode.constants.ERROR_CORRECT_H,
#         box_size=10,
#         border=4,
#     )
#     qr.add_data(payload)
#     qr.make(fit=True)
#     img = qr.make_image(fill_color="black", back_color="white")

#     # Buffer to image
#     buffer = io.BytesIO()
#     img.save(buffer, format="PNG")
#     buffer.seek(0)
#     filename = f"{ticket_number}.png"
#     qrcode_ticket = QrcodeTicket.objects.create(
#         event_booking_ticket_id=booking_ticket_id, ticket_number=ticket_number
#     )
#     qrcode_ticket.qr_code.save(filename, ContentFile(buffer.read()), save=False)
#     qrcode_ticket.save()
#     buffer.close()
#     return True


def image_to_base64(image_field):
    if not image_field:
        return ""
    with default_storage.open(image_field.name, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read()).decode("utf-8")
        return f"data:image/png;base64,{encoded_string}"


class Base64ImageField(ImageField):
    """
    A Django REST Framework field for handling image uploads via base64 strings
    and returning the absolute URL of the image on serialization.
    """

    def to_internal_value(self, data):
        if isinstance(data, str) and data.startswith("data:image"):
            try:
                format, imgstr = data.split(";base64,")
                ext = format.split("/")[-1]
                decoded_file = base64.b64decode(imgstr)
            except Exception:
                raise serializers.ValidationError("Invalid base64 image string")

            file_name = f"{uuid.uuid4()}.{ext}"
            data = ContentFile(decoded_file, name=file_name)

        return super().to_internal_value(data)

    def to_representation(self, value):
        """
        Return the full absolute URL for the image.
        """
        if not value:
            return None
        request = self.context.get("request", None)
        if request is not None:
            return request.build_absolute_uri(value.url)
        return super().to_representation(value)


class Base64ImageField(ImageField):
    """
    A Django REST Framework field for handling image uploads via base64 strings
    and returning the absolute URL of the image on serialization.
    """

    def to_internal_value(self, data):
        if isinstance(data, str) and data.startswith("data:image"):
            try:
                format, imgstr = data.split(";base64,")
                ext = format.split("/")[-1]
                decoded_file = base64.b64decode(imgstr)
            except Exception:
                raise serializers.ValidationError("Invalid base64 image string")

            file_name = f"{uuid.uuid4()}.{ext}"
            data = ContentFile(decoded_file, name=file_name)

        return super().to_internal_value(data)

    def to_representation(self, value):
        """
        Return the full absolute URL for the image.
        """
        if not value:
            return None
        request = self.context.get("request", None)
        if request is not None:
            return request.build_absolute_uri(value.url)
        return super().to_representation(value)


# def verify_uat_signature(signature_string: str, base64_signature: str) -> bool:
#     # try:
#     # cert_pem_str = "-----BEGIN CERTIFICATE-----\nMIIDZjCCAk6gAwIBAgIKbazp0wAFAAACqTANBgkqhkiG9w0BAQsFADAaMRgwFgYD\nVQQDEw9NWVRFU1RJU1NVRVItQ0EwHhcNMjEwNjIyMDQ1NTU5WhcNMjIxMjEyMDc0\nMTM2WjCBgjELMAkGA1UEBhMCTlAxEDAOBgNVBAgTB0JhZ21hdGkxEjAQBgNVBAcT\nCUthdGhtYW5kdTEMMAoGA1UEChMDTlFSMQwwCgYDVQQLEwNOUVIxDDAKBgNVBAMT\nA05RUjEjMCEGCSqGSIb3DQEJARYUbm8tcmVwbHlAbmNobC5jb20ubnAwgZ8wDQYJ\nKoZIhvcNAQEBBQADgY0AMIGJAoGBAMbIIkH+0JOZKdOVT7Wr3gPOQpvk9pwQ2gME\n2p7UIdDlxg2KjblMLRsWNnh11mcVvF8EiTFXSJnXGQeH7uunMpea5vKqshkLVoa2\nGjRDtLmgnQ09ALWzeHRFBKiAaxwSUq6g0+o9q3Fwbox4W7wrcRqdjU1FW6/3IGxv\n8aLniE2VAgMBAAGjgcgwgcUwDgYDVR0PAQH/BAQDAgTwMBMGA1UdJQQMMAoGCCsG\nAQUFBwMCMB0GA1UdDgQWBBTUsl7hag3HSDMQWE/LvTWNltOK1jAfBgNVHSMEGDAW\ngBTe1c5iHw892GWgw9yxIQgoxQm46TBeBggrBgEFBQcBAQRSMFAwTgYIKwYBBQUH\nMAKGQmZpbGU6Ly9teXRlc3Rpc3N1ZXIvQ2VydEVucm9sbC9teXRlc3Rpc3N1ZXJf\nTVlURVNUSVNTVUVSLUNBKDUpLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA21H5nQYI\ncH4oSid+qFfwgylMq8sfjOtIKtma2u97UDEstOztRBxDUDY/xzgxKqYKIO4okJAX\nFgsef26xRI8uLbu1BJoyX8PGdWbe4KCvfNXrARnc5wSpYLwNTczqTOBhZdhTGJP3\nJxMYRNEL1d3n33bwJD3jrSAebLlHX8S/RC6YVC60pb9juHA8Ln+cwkNQSFD+qEzt\n4Ysr5lNWSTaNex8zsYjbLCcER41pEFk6w8qmY6/yQagw710FioZzhJuTWxz3o5N1\nNVf5P/lSBQgNSbMBLXkKjHT1dPQaM03sk/nJ2YSKA0PeeM/ZjZTsQ+eDrovvbNZF\nvzlfmIJcTY5cCQ==\n-----END CERTIFICATE-----"

#     cert_pem_str = os.environ.get("NCHL_CERTIFICATE")
#     # try:
#     cert = load_pem_x509_certificate(cert_pem_str.encode(), default_backend())
#     public_key = cert.public_key()

#     decoded_signature = base64.b64decode(base64_signature)

#     public_key.verify(
#         decoded_signature,
#         signature_string.encode("utf-8"),
#         padding.PKCS1v15(),
#         hashes.SHA256(),
#     )

#     return True
#     # except InvalidSignature:
#     #     print("Invalid signature")
#     #     return False
#     # except Exception as e:
#     #     print(f"Verification error: {e}")
#     #     return False
#     # except Exception as e:
#     #     print(f"Signature verification failed: {e}")
#     #     return False


# def verify_signature(signature_string: str, base64_signature: str) -> bool:
#     public_key_pem = """-----BEGIN PUBLIC KEY-----
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqoLwlLr8zh/Rje6H/4KV
# 6sIYJ3VOM+7EglPPbDFwI2uOvm18pS2OXoZfZeq2+FpWM8B6IckLd+HolQAp6yDA
# LvU7SrLlRpZAtDywRB3if4vHlvZbjYkHUa+CCK9f5Q95neIZv3+t/ZBZaFiguM2s
# 4qMhTnE3p/ZvS/sMKfdwhPCrn66OuSrOxfWAQhCTGdBiTgo3H3SVlRDCb81RFu/s
# 2g+SXROib+RcEZfcasN2EmoYKJnERbwe3GN3V6EdSMSeg2RvgvybirCA1UikOalL
# ruieTfYZQItMvo9jx48spI+gnQg8a+Mq/rCikQMkxyPfYGCOQ1u9/exIzG7PTmxb
# oQIDAQAB
# -----END PUBLIC KEY-----"""

#     public_key = serialization.load_pem_public_key(public_key_pem.encode())
#     decoded_signature = base64.b64decode(base64_signature)

#     public_key.verify(
#         decoded_signature,
#         signature_string.encode(),
#         padding.PKCS1v15(),
#         hashes.SHA256(),
#     )
#     return True


def generate_transaction_id():
    date_part = datetime.now().strftime("%y%m%d")  # e.g., 250728
    number_part = f"{random.randint(0, 9999999999):010d}"  # 10-digit zero-padded number
    return date_part + number_part


class SearchQueryMixin:
    def apply_search(self, queryset, request, search_fields, delimiter=","):
        """
        Applies a search filter to a Django queryset based on query parameters and a list of searchable fields.

        This method allows dynamic, multi-field, multi-term search functionality. It parses the 'search' parameter
        from the request's query string and constructs a complex query to filter the queryset. Each term in the
        search string is matched (case-insensitively) against each field provided in the `search_fields` list.

        Search behavior:
            - The `search` parameter is split by the given delimiter (default is comma `,`) into individual search terms.
            - Each term is checked against all specified fields using `icontains` lookup, meaning partial matches are allowed.
            - All terms must match at least one of the fields (i.e., terms are combined using AND logic).
            - Each term is checked against all fields using OR logic.

        Example:
            If `search_fields = ["name", "description"]` and the query is `?search=music,festival`,
            this will generate a query equivalent to:
                (name__icontains="music" OR description__icontains="music")
                AND
                (name__icontains="festival" OR description__icontains="festival")

        Args:
            queryset (QuerySet): The original queryset to apply the search filter on.
            request (Request): The HTTP request object containing query parameters.
            search_fields (list): A list of model field names to search against (supports related fields using lookups).
            delimiter (str): The character used to separate multiple search terms in the query parameter. Default is ','.

        Returns:
            QuerySet: A filtered queryset containing only results that match the search criteria.
        """
        search_param = request.query_params.get("search", "")

        if not search_fields or not search_param:
            return queryset

        terms = [term.strip() for term in search_param.split(delimiter) if term.strip()]
        if not terms:
            return queryset

        query = Q()
        for term in terms:
            subquery = Q()
            for field in search_fields:
                subquery |= Q(**{f"{field}__icontains": term})
            query &= subquery

        return queryset.filter(query)


def slugify_for_models(slug, name, model_class):
    if slug:
        return slug  # Allow explicit slug override

    base = slugify(name)[:200]
    slug_candidate = base
    num = 1
    while model_class.objects.filter(slug=slug_candidate).exists():
        slug_candidate = f"{base}-{num}"
        num += 1
    return slug_candidate
