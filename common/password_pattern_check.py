from django.core.exceptions import ValidationError
import re


def check_password_pattern_in_validation_serializers(password_check):
    # NOTE: validator for serializers validate function
    if not password_check or len(password_check) < 8:
        raise ValidationError("Password must be at least 8 characters long.")

    # Regex to ensure at least 1 uppercase, 1 digit, 1 special char
    if not re.match(
        r'^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).+$', password_check
    ):
        raise ValidationError(
            "Password must contain at least one uppercase letter, one number, and one special character."
        )
