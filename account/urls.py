from django.urls import path

from account import views
from rest_framework.routers import DefaultRouter


urlpatterns = [
    path("register/", views.RegisterView.as_view()),
    path(
        "signup-verify/",
        views.SignupVerifyAPIView.as_view(),
        name="signup_verify",
    ),
    path("login/", views.LoginView.as_view()),
    path("resend-otp/", views.ResendOTP.as_view()),
    # path("setup-totp/", views.SetupTOTPView.as_view()),
    # path("verify-otp/", views.OTPVerifyView.as_view()),
    # path("send-otp/", views.SendMailOTP.as_view()),
    # path("email-otp-verify/", views.EmailOtpVerify.as_view()),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path(
        "token/refresh/", views.CustomTokenRefreshView.as_view(), name="token_refresh"
    ),
    path("request/password-reset/", views.RequestForForgetPassword.as_view()),
    path(
        "password-reset/",
        views.ForgetPasswordConfirm.as_view(),
    ),
    path("change-password/", views.ChangePasswordView.as_view()),
    path("profile/", views.UserProfileUpdateView.as_view(), name="user-profile"),
    path("social-auth/", views.GoogleLoginAPIView.as_view(), name="social-auth"),
]
