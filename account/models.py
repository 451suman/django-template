from django.db import models

import random

import pyotp
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator

from common.models import TimestampedModel

phone_validator = RegexValidator(
    regex=r"^\+?1?\d{9,15}$",
    message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.",
)


class UserAccountManager(BaseUserManager):
    def create_user(self, email, full_name, phone_no, password=None, **extra_fields):
        if not email:
            raise ValueError(_("The Email field must be set"))

        email = self.normalize_email(email)
        user = self.model(
            email=email, full_name=full_name, phone_no=phone_no, **extra_fields
        )
        user.set_password(password)
        user.is_active = True
        user.is_verified = True
        user.save()
        return user

    def create_superuser(
        self, email, full_name, phone_no, password=None, **extra_fields
    ):
        extra_fields.setdefault("is_admin", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_admin") is not True:
            raise ValueError(_("Superuser must have is_admin=True."))

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))

        return self.create_user(email, full_name, phone_no, password, **extra_fields)


class UserAccount(AbstractBaseUser, PermissionsMixin):
    STATUS_CHOICES = [
        ("pending", _("Pending")),
        ("verified", _("Verified")),
        ("blocked", _("Blocked")),
    ]

    email = models.EmailField(max_length=255, unique=True)
    phone_no = models.CharField(
        validators=[phone_validator],
        max_length=16,
        unique=True,
        null=True,
        blank=True,
    )
    full_name = models.CharField(max_length=255)
    date_of_birth = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=False)
    is_verified = models.BooleanField(_("is_verified"), default=False)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(_("admin"), default=False)
    is_merchant = models.BooleanField(_("merchant"), default=False)
    is_partner = models.BooleanField(_("partner"), default=False)
    otp = models.CharField(max_length=256, null=True, blank=True)
    otp_generated_at = models.DateTimeField(null=True, blank=True)
    activation_key = models.CharField(max_length=150, blank=True, null=True)
    is_2fa_enabled = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=32, blank=True, null=True)
    totp_secret_qr = models.TextField(
        blank=True, null=True, help_text="QR Code for 2FA in base64"
    )

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")
        ordering = ["-id"]

    objects = UserAccountManager()
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["full_name", "phone_no"]

    def get_full_name(self):
        return f"{self.full_name}"

    def generate_totp_secret(self):
        if not self.totp_secret:
            self.totp_secret = pyotp.random_base32()
            self.save()

    def get_totp_uri(self):
        return f"otpauth://totp/MyPayEventsAndVoting:{self.full_name}?secret={self.totp_secret}&issuer=MyPayEventsAndVoting"

    def verify_totp(self, otp):
        return pyotp.TOTP(self.totp_secret).verify(otp)

    def generate_otp(self):
        """Generate a 6-digit random OTP and store it with a timestamp."""
        otp = f"{random.randint(100000, 999999)}"
        self.otp = otp
        self.otp_generated_at = timezone.now()
        self.save()
        return otp

    def verify_otp(self, otp):
        """Verify if the OTP matches and is not expired."""

        if (
            self.otp == otp
            and timezone.now() - self.otp_generated_at <= timezone.timedelta(minutes=5)
        ):
            return True
        return False

    def __str__(self):
        return f"{self.full_name}"


class BlacklistedAccessToken(models.Model):
    jti = models.CharField(max_length=255, unique=True)
    user_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Blacklisted Token JTI: {self.jti}"


class LoginAttempt(models.Model):
    user = models.OneToOneField("UserAccount", on_delete=models.CASCADE)
    failed_attempts = models.IntegerField(default=0)
    is_locked = models.BooleanField(default=False)

    def reset_attempts(self):
        self.failed_attempts = 0
        self.is_locked = False
        self.save()

    def increment_attempts(self):
        self.failed_attempts += 1
        if self.failed_attempts >= 5:
            self.is_locked = True
        self.save()

    def checked_locked(self):
        return self.is_locked


class UserProfile(TimestampedModel):
    user = models.OneToOneField(
        UserAccount, on_delete=models.CASCADE, related_name="profile"
    )
    bio = models.TextField(null=True, blank=True)
    profile_image = models.ImageField(
        upload_to="profile_images/",
        blank=True,
        null=True,
        help_text="Profile picture of the user",
    )
    social_auth_profile_link = models.URLField(null=True, blank=True)
