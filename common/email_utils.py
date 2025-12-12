from django.conf import settings
from django.core.files.storage import default_storage
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.core.mail import EmailMessage, EmailMultiAlternatives


def send_activation_success_email(user_email):
    # Rendering the email template
    email_template = render_to_string("signup_success.html", {"username": user_email})

    # Creating and sending the email
    sign_up = EmailMultiAlternatives(
        "Account successfully activated",
        "Account successfully activated",
        settings.EMAIL_HOST_USER,
        [user_email],
    )
    sign_up.attach_alternative(email_template, "text/html")
    sign_up.send()
