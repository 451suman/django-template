from django.utils import timezone
import hashlib
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework import serializers
from common.password_pattern_check import (
    check_password_pattern_in_validation_serializers,
)
from common.utils import GenerateKey
from .models import UserAccount, UserProfile


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    otp = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = UserAccount
        fields = ("email", "full_name", "password", "date_of_birth", "phone_no", "otp")

    def create(self, validated_data):

        key = GenerateKey.return_value()
        hashed_otp = hashlib.sha256(key.encode("utf-8")).hexdigest()

        # Validate and set password
        password = validated_data.pop("password")
        # Create CustomUser instance
        user = UserAccount.objects.create_user(
            email=validated_data["email"],
            phone_no=validated_data["phone_no"],
            full_name=validated_data["full_name"],
            # date_of_birth=validated_data["date_of_birth"],
            otp=hashed_otp,
            password=password,
        )
        user.otp_generated_at = timezone.now()
        user.is_verified = False
        user.is_active = False
        user.save()

        return user.email, key


class UserProfileSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(
        source="user.full_name", required=False, write_only=True
    )
    email = serializers.EmailField(source="user.email", required=False, write_only=True)

    class Meta:
        model = UserProfile
        fields = [
            "id",
            "full_name",
            "email",
            "user",
            "bio",
            "profile_image",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["user", "created_at", "updated_at"]

    def update(self, instance, validated_data):
        # Update nested user fields if provided
        user_data = validated_data.pop("user", {})
        if "full_name" in user_data:
            instance.user.full_name = user_data["full_name"]
        if "email" in user_data:
            instance.user.email = user_data["email"]
        instance.user.save()

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

    def to_representation(self, instance):
        new_instance = super().to_representation(instance)
        request = self.context.get("request")
        new_instance["user"] = {
            "id": instance.user.id,
            "full_name": instance.user.full_name,
            "email": instance.user.email,
            "phone_no": instance.user.phone_no,
        }

        new_instance["profile_image"] = (
            request.build_absolute_uri(instance.profile_image.url)
            if instance.profile_image
            else instance.social_auth_profile_link
        )
        return new_instance
