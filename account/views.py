# import qrcode
import requests
import base64
import io
import re
import hashlib
import threading
from datetime import timedelta

from django.shortcuts import render
from django.contrib.auth import get_user_model
from django.utils import timezone

from django.conf import settings
from django.core.mail import send_mail
from django.contrib.auth.hashers import check_password
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.permissions import IsAuthenticated, AllowAny

from common.base_views import BaseAPIViewSet

# from account.models import LoginAttempt, UserAccount
from .models import LoginAttempt, UserProfile
from .models import UserAccount
from account.serializers import RegisterSerializer, UserProfileSerializer
from common.response import error_response, success_response
from common.utils import (
    send_activation_success_email,
    send_verification_email,
)
from common.utils import GenerateKey

User = get_user_model()


# later this should be placed inside common folder
def check_password_pattern_in_views(password_check):
    if not re.match(
        r'^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).+$', password_check
    ):
        return error_response(
            message="Invalid password format",
            errors="Password must contain at least one uppercase letter, one number, and one special character.",
        )

    if not password_check or len(password_check) < 8:
        return error_response(
            message="Invalid password length",
            errors="Password must be at least 8 characters long.",
        )
    return None


class RegisterView(generics.CreateAPIView):
    queryset = UserAccount.objects.all()
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        password_check = request.data.get("password")
        email = request.data.get("email")
        required_fields = ["email", "phone_no", "full_name"]
        errors = {}

        for field in required_fields:
            value = request.data.get(field)
            if not value:
                # Create a human-readable label for the field
                field_label = field.replace("_", " ").capitalize()
                errors[field] = f"{field_label} is required"

        if errors:
            return error_response(message="Missing required fields", errors=errors)
        password_validation_response = check_password_pattern_in_views(password_check)
        if password_validation_response:
            return password_validation_response
        try:
            # Check if user already exists (e.g., via Google/Facebook login)
            existing_user = UserAccount.objects.get(email=email)
            # User exists – set new password and send OTP
            otp_raw = GenerateKey.return_value()
            hashed_otp = hashlib.sha256(otp_raw.encode("utf-8")).hexdigest()
            existing_user.set_password(password_check)
            existing_user.otp = hashed_otp
            existing_user.otp_generated_at = timezone.now()
            existing_user.save()

            # Send email in background
            threading.Thread(
                target=send_verification_email, args=[existing_user.email, otp_raw]
            ).start()

            return success_response(
                message="User already existed. Password set. Please verify the OTP sent to your email."
            )

        except UserAccount.DoesNotExist:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                user, otp = serializer.save()
                send_email = threading.Thread(
                    target=send_verification_email, args=[user, otp]
                )
                send_email.start()
                # user.otp_generated_at = timezone.now()
                return success_response(
                    message="User has been registered please verify the OTP sent to your email",
                    # data=serializer.data,
                )
            return error_response(
                message="Failed to Register User", errors=serializer.errors
            )


class SignupVerifyAPIView(APIView):
    def post(self, request):
        otp = request.data.get("otp")
        if not otp:
            return error_response(message="Otp is required.")

        hashed_otp = hashlib.sha256(otp.encode("utf-8")).hexdigest()

        try:
            user = User.objects.get(otp=hashed_otp)
        except User.DoesNotExist:
            return error_response(message="Invalid otp", errors="Invalid otp")

        if user.is_active == False and user.is_verified == True:
            return error_response(
                message="User is not active.", errors="User is not active."
            )

        if (
            not user.otp_generated_at
            or user.otp_generated_at + timedelta(minutes=1) < timezone.now()
        ):
            return error_response(message="OTP has expired", errors="OTP has expired")

        # OTP is valid and not expired; verify user
        user.is_verified = True
        user.is_active = True
        user.otp = None

        user.save()

        profile, created = UserProfile.objects.get_or_create(user=user)

        thread = threading.Thread(
            target=send_activation_success_email, args=(user.email,)
        )
        thread.start()

        return success_response(
            message="Your account has been successfully activated!!"
        )

        # except:
        #     return error_response(
        #         message="Invalid otp OR No any inactive user found for given otp",
        #         errors="Invalid otp OR No any inactive user found for given otp",
        #     )


class LoginView(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return error_response(
                message="User not found.",
                errors="User not found.",
            )

        if user:
            attempt, _ = LoginAttempt.objects.get_or_create(user=user)
            if attempt.checked_locked():
                return Response(
                    {
                        "success": False,
                        "message": "Your account has been temporarily locked due to multiple failed login attempts.",
                        "errors": "Account locked",
                        "failed_attempts": attempt.failed_attempts,
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        loginattemp_user = LoginAttempt.objects.filter(user=user).first()
        if not user.check_password(password):
            loginattemp_user.increment_attempts()
            return Response(
                {
                    "success": False,
                    "message": "Invalid username or password.",
                    "errors": "Invalid username or password.",
                    "failed_attempts": loginattemp_user.failed_attempts,
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        if user.is_superuser == False:
            if user.is_active == False and user.is_verified == True:
                return Response(
                    {
                        "success": False,
                        "message": "User is not active",
                        "data": None,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            elif user.is_verified == False and user.is_active == False:
                otp_raw = GenerateKey.return_value()
                hashed_otp = hashlib.sha256(otp_raw.encode("utf-8")).hexdigest()
                user.otp = hashed_otp
                user.otp_generated_at = timezone.now()
                user.save()

                # Send email in background
                threading.Thread(
                    target=send_verification_email, args=[user.email, otp_raw]
                ).start()

                return Response(
                    {
                        "success": False,
                        "message": "User is not verified, if email exists then otp has been sent.",
                        # "is_active": user.is_active,
                        "is_verified": user.is_verified,
                        "data": None,
                    },
                    status=status.HTTP_200_OK,
                )

        loginattemp_user.reset_attempts()
        permission = user.get_all_permissions()
        if user.is_2fa_enabled == False:
            refresh = RefreshToken.for_user(user)
            if user.is_superuser or user.is_staff:
                user_type = "admin"
            elif hasattr(user, "is_merchant") and user.is_merchant:
                user_type = "merchant"
            else:
                user_type = "user"
            return Response(
                {
                    "success": True,
                    "message": "Login successful",
                    # "is_active": user.is_active,
                    "is_verified": user.is_verified,
                    "data": {
                        # "merchant": user.full_name if user.is_merchant else None,
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                        # "is_active": user.is_active,
                        "full_name": user.full_name,
                        "email": user.email,
                        "phone_no": user.phone_no,
                        "date_of_birth": user.date_of_birth,
                        "totp_required": False,
                        "type": user_type,
                        "permissions": permission,
                        "auth_type": "normal-system",
                    },
                },
                status=status.HTTP_200_OK,
            )

            # return success_response(
            #     {
            #         # "merchant": user.full_name if user.is_merchant else None,
            #         "refresh": str(refresh),
            #         "access": str(refresh.access_token),
            #         # "is_active": user.is_active,
            #         "is_verified": user.is_verified,
            #         "full_name": user.full_name,
            #         "email": user.email,
            #         "phone_no": user.phone_no,
            #         "date_of_birth": user.date_of_birth,
            #         "totp_required": False,
            #         "type": user_type,
            #         "permissions": permission,
            #         "auth_type": "normal-system",
            #     }
            # )
        if user.is_2fa_enabled == True:
            # Check if user has TOTP enabled
            if not user.totp_secret:
                # 2FA not set up, return JWT tokens immediately (password-only login)
                refresh = RefreshToken.for_user(user)
                return success_response(
                    {
                        "merchant": (user.full_name if user.is_merchant else None),
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                        "totp_required": True,
                    }
                )
            # If TOTP is enabled, require OTP next step (don't issue tokens yet)
            return success_response(
                {
                    "message": "2FA enabled. Please provide OTP to continue.",
                    "totp_required": True,
                },
                status=status.HTTP_202_ACCEPTED,
            )


class ResendOTP(APIView):
    def post(self, request):
        email = request.data.get("email")
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return error_response("User not found.")
        otp_raw = GenerateKey.return_value()
        hashed_otp = hashlib.sha256(otp_raw.encode("utf-8")).hexdigest()
        user.otp = hashed_otp
        user.otp_generated_at = timezone.now()
        user.save()
        # Send email in background
        threading.Thread(
            target=send_verification_email, args=[user.email, otp_raw]
        ).start()

        return success_response(message="OTP sent successfully.")


class SetupTOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user.generate_totp_secret()
        uri = user.get_totp_uri()

        img = qrcode.make(uri)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_b64 = base64.b64encode(buffer.getvalue()).decode()
        user.totp_secret_qr = f"data:image/png;base64,{qr_b64}"
        user.save()
        return success_response(
            {
                "totp_secret": user.totp_secret,
                "uri": uri,
                "qr_image_base64": f"data:image/png;base64,{qr_b64}",
            }
        )


class OTPVerifyView(APIView):
    # permission_classes = [IsAuthenticated]

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return error_response("User not found")
        if not user.is_verified:
            return error_response("User is not verified.")
        if not user.is_staff:
            return error_response("User is not a merchant.")

        user.is_active = True
        user.is_verified = True
        # if not user.verify_totp(otp):
        #     return error_response("Invalid or expired OTP")

        # OTP valid, issue tokens
        refresh = RefreshToken.for_user(user)
        return success_response(
            {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }
        )


class SendMailOTP(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return error_response("User not found.")
        if user.is_2fa_enabled == True:
            if not user.check_password(password):
                return error_response("Invalid password.")
            if not user.is_active:
                return error_response("User is not active.")
            if not user.is_verified:
                return error_response("User is not verified.")
            if not user.is_staff:
                return error_response("User is not a merchant.")
            # function is in model.py
            otp = user.generate_otp()

            send_mail(
                "Login 2FA Verification OTP",
                f"Your OTP for login is: {otp}",
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            return success_response("2FA verification code sent to your email.")
        else:
            return error_response("2FA is not enabled for this user. REDIRECT TO LOGIN")


class EmailOtpVerify(APIView):
    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        user = User.objects.get(email=email)
        if user.verify_otp(otp) == False:
            return error_response("Invalid OTP.")
        if not user.is_active:
            return error_response("User is not active.")

        if not user.is_verified:
            return error_response("User is not verified")
        if not user.is_staff:
            return error_response("User is not a merchant.")
        # OTP valid, issue tokens
        refresh = RefreshToken.for_user(user)
        return success_response(
            {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }
        )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # refresh_token = request.data.get("refresh")
        # access_token = request.data.get("access")
        # if not refresh_token or not access_token:
        #     return error_response("Refresh and Access tokens are required.")
        # try:
        #     # Blacklist refresh token
        #     refresh = RefreshToken(refresh_token)
        #     refresh.blacklist()

        #     # Blacklist access token in Redis
        #     # access = AccessToken(access_token)
        #     # jti = access["jti"]
        #     # exp_timestamp = access["exp"]
        #     # expires = datetime.fromtimestamp(exp_timestamp, tz=pytz.UTC)
        #     # ttl = int((expires - datetime.now(tz=pytz.UTC)).total_seconds())

        #     # Store the jti in Redis with expiry
        #     # cache.set(f"blacklist_{jti}", "true", timeout=ttl)

        # except TokenError:
        #     return error_response("Invalid token.")

        return success_response(message="Logout successful.", data=None)


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            error_msg = e.args[0]
            if "Token is blacklisted" in error_msg:
                return error_response(
                    message="Token is blacklisted.",
                    errors="Token is blacklisted.",
                    status=status.HTTP_403_FORBIDDEN,
                )
            elif (
                "Token is invalid or expired" in error_msg
                or "expired" in error_msg.lower()
            ):
                return error_response(
                    message="Token is expired.",
                    errors="Token is expired.",
                    status=status.HTTP_403_FORBIDDEN,
                )
            #     return Response(
            #         {"detail": "Token is expired."}, status=status.HTTP_403_FORBIDDEN
            #     )
            # return Response({"detail": error_msg}, status=status.HTTP_400_BAD_REQUEST)
            return error_response(
                message=error_msg,
                errors=error_msg,
                status=status.HTTP_400_BAD_REQUEST,
            )

        # return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return success_response(
            message="Token refreshed successfully.",
            data=serializer.validated_data,
            status=status.HTTP_200_OK,
        )


class RequestForForgetPassword(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")

        if not email:
            return error_response(
                message="Email is required",
                errors="Missing email in request",
            )

        try:
            user_object = UserAccount.objects.get(email=email)
        except UserAccount.DoesNotExist:
            return error_response(
                message="Account not found",
                errors="Account not found",
            )

        try:
            generated_otp = user_object.generate_otp()
            user_object.otp = base64.b64encode(generated_otp.encode()).decode()
            user_object.save()
            send_mail(
                "Password Reset OTP",
                f"Your OTP for resetting your password is: {generated_otp}",
                settings.EMAIL_HOST_USER,
                [user_object.email],
                fail_silently=False,
            )

            return success_response(
                message="OTP has been sent to your email",
            )

        except Exception as e:
            return error_response(
                message="Failed to send OTP",
                errors=str(e),
            )


class ForgetPasswordConfirm(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        received_otp = request.data.get("otp")
        hash_otp = base64.b64encode(received_otp.encode()).decode()
        try:
            user = User.objects.get(otp=hash_otp)
        except User.DoesNotExist:
            return error_response(
                message="Invalid OTP.",
                errors="Invalid OTP.",
            )
        if user.is_active == False and user.is_verified == True:
            return error_response(
                message="Account is not active.",
                errors="Account is not active.",
            )
        new_password = request.data.get("new_password")
        password_validation_response = check_password_pattern_in_views(new_password)
        if password_validation_response:
            return password_validation_response

        if not new_password:
            return error_response(
                message="New password is required.",
                errors="New password is required.",
            )

        # Check OTP expiration (2 minutes)
        if timezone.now() - user.otp_generated_at > timedelta(minutes=3):

            return error_response(
                message="OTP has expired.",
                errors="OTP has expired.",
            )

        # Prevent reusing old password
        if check_password(new_password, user.password):
            return Response(
                {
                    "success": False,
                    "message": "The new password cannot be the same as the current password.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Update password securely
        user.set_password(new_password)
        user.otp = None
        user.otp_generated_at = None
        user.save()
        loginAttemp_user = LoginAttempt.objects.filter(user=user).first()
        loginAttemp_user.reset_attempts()
        send_mail(
            "Password changed successfully",
            f"Your password has been reset successfully.",
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False,
        )

        return success_response(message="Password reset successful.")


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        # Require old_password for regular users
        if not user.check_password(old_password):
            return error_response(
                message="Failed to change password.",
                errors="Old password is incorrect.",
            )

        if new_password != confirm_password:
            return error_response(
                message="Failed to change password.", errors="Passwords do not match."
            )

        password_validation_response = check_password_pattern_in_views(confirm_password)
        if password_validation_response:
            return password_validation_response

        user.set_password(new_password)
        user.save()

        return success_response(message="Password changed successfully.", data=None)


class UserProfileUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        try:
            profile = UserProfile.objects.get(user=request.user)
        except:
            profile = UserProfile.objects.get_or_create(user=request.user)

        serializer = UserProfileSerializer(
            profile, data=request.data, partial=True, context={"request": request}
        )
        if serializer.is_valid():
            serializer.save()
            return success_response(
                message="Profile Updated Successfully",
                data=serializer.data,
                status=status.HTTP_200_OK,
            )
        return error_response(
            errors=serializer.errors, status=status.HTTP_400_BAD_REQUEST
        )

    def put(self, request):
        try:
            profile = UserProfile.objects.get(user=request.user)
        except:
            profile = UserProfile.objects.get_or_create(user=request.user)

        serializer = UserProfileSerializer(
            profile, data=request.data, partial=True, context={"request": request}
        )
        if serializer.is_valid():
            serializer.save()
            return success_response(
                message="Profile Updated Successfully",
                data=serializer.data,
                status=status.HTTP_200_OK,
            )
        return error_response(
            errors=serializer.errors, status=status.HTTP_400_BAD_REQUEST
        )

    def get(self, request):
        try:
            profile, _ = UserProfile.objects.get_or_create(user=request.user)
        except UserProfile.DoesNotExist:
            return error_response(
                errors={"detail": "Profile not found"}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = UserProfileSerializer(profile, context={"request": request})
        return success_response(
            message="profile fetched", data=serializer.data, status=status.HTTP_200_OK
        )


# views.py

from google.oauth2 import id_token
from google.auth.transport import requests


def google_login(request, id_token_received):

    try:
        idinfo = id_token.verify_oauth2_token(id_token_received, requests.Request())
    except Exception as e:
        return Response(
            {"success": False, "message": str(e)},
            status=status.HTTP_400_BAD_REQUEST,
        )
    email = idinfo.get("email")
    full_name = idinfo.get("name")

    user_picture = idinfo.get("picture")
    if not email:
        # return Response({"error": "Email not available from Google"}, status=400)
        return error_response(
            message="Email not available from Google",
            errors="Email not available from Google",
        )
    if idinfo.get("email_verified") != True:
        return error_response(
            message="Email not verified from Google",
            errors="Email not verified from Google",
        )
    # Create or get user
    try:
        user, created = User.objects.get_or_create(
            email=email,
        )
        if not hasattr(user, "profile"):
            profile = UserProfile.objects.create(user=user)

        if not user.profile.profile_image or not user.profile.social_auth_profile_link:
            user.profile.social_auth_profile_link = idinfo.get("picture")
            user.profile.save()

        user.is_active = True
        user.is_verified = True

        if not user.full_name:
            user.full_name = full_name

        user.save()
    except Exception as e:
        return error_response(message="User creation failed", errors=str(e))

    permission = user.get_all_permissions()
    # Issue JWT tokens
    refresh = RefreshToken.for_user(user)
    return Response(
        {
            "success": True,
            "message": "Login successful",
            "data": {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "full_name": user.full_name,
                "email": user.email,
                "phone_no": user.phone_no if user.phone_no else None,
                "date_of_birth": user.date_of_birth if user.date_of_birth else None,
                "totp_required": False,
                "type": "user",
                "permission": permission,
                "picture": user_picture,
                "auth_type": "google_login",
            },
        }
    )


# def google_login(request, id_token):
#     google_user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo"
#     headers = {"Authorization": f"Bearer {id_token}"}
#     response = requests.get(google_user_info_url, headers=headers)
#     if response.status_code != 200:
#         # return Response({"error": "Invalid Google token"}, status=400)
#         return error_response(
#             message="Invalid Google token", errors="Invalid Google token"
#         )
#     user_info = response.json()
#     email = user_info.get("email")
#     first_name = user_info.get("given_name")
#     last_name = user_info.get("family_name")

#     if not email:
#         # return Response({"error": "Email not available from Google"}, status=400)
#         return error_response(
#             message="Email not available from Google",
#             errors="Email not available from Google",
#         )
#     # Create or get user
#     try:
#         user, created = User.objects.get_or_create(
#             email=email,
#             full_name=first_name + " " + last_name,
#             is_verified=True,
#             is_active=True,
#         )
#     except Exception as e:
#         return error_response(message="User creation failed", errors=str(e))

#     permission = user.get_all_permissions()
#     # Issue JWT tokens
#     refresh = RefreshToken.for_user(user)
#     return Response(
#         {
#             "success": True,
#             "message": "Login successful",
#             "data": {
#                 "refresh": str(refresh),
#                 "access": str(refresh.access_token),
#                 "full_name": user.full_name,
#                 "email": user.email,
#                 "phone_no": user.phone_no if user.phone_no else None,
#                 "date_of_birth": user.date_of_birth if user.date_of_birth else None,
#                 "totp_required": False,
#                 "type": "user",
#                 "permission": permission,
#             },
#         }
#     )


class GoogleLoginAPIView(APIView):
    def post(self, request):
        id_token = request.data.get("id_token")
        auth_type = request.data.get("auth_type")
        auth_type_list = ["google"]
        if auth_type not in auth_type_list:
            return error_response(
                message="Invalid authentication type",
                errors="Invalid authentication type",
            )
        if not id_token:
            # return Response({"error": "Access token is required"}, status=400)
            return error_response(
                message="Access token is required",
                errors="access_token field is required",
            )
        if auth_type == "google":
            # Verify token with Google
            return google_login(request, id_token)
        else:
            return error_response(
                message="Invalid authentication type",
                errors="Invalid authentication type",
            )
        # if auth_type == "facebook":
        #     # Verify token with facebook
        #     return facebook_login(request, id_token)


# def facebook_login(request, id_token):
#     # Verify token with Facebook and get user info
#     user_info_url = "https://graph.facebook.com/me"
#     params = {
#         "access_token": id_token,
#         "fields": "id,email,name",
#     }
#     response = requests.get(user_info_url, params=params)
#     if response.status_code != 200:
#         return error_response("Invalid Facebook token")

#     data = response.json()
#     email = data.get("email")
#     full_name = data.get("name")

#     if not email:
#         return error_response("Email not returned by Facebook")

#     # Create or get user
#     try:
#         user, created = User.objects.get_or_create(full_name=full_name)
#     except Exception as e:
#         return error_response(message="User creation failed", errors=str(e))

#     # Issue tokens
#     refresh = RefreshToken.for_user(user)
#     return Response(
#         {
#             "refresh": str(refresh),
#             "access": str(refresh.access_token),
#         }
#     )
