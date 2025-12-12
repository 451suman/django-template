from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from account.models import UserAccount, UserProfile
from common.password_pattern_check import (
    check_password_pattern_in_validation_serializers,
)


class AdminUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    phone_no = serializers.CharField(required=True)

    class Meta:
        model = UserAccount
        fields = [
            "id",
            "email",
            "full_name",
            "password",  # Only used on create
            "phone_no",
            "is_active",
            "is_verified",
            "is_staff",
            "is_admin",
        ]
        extra_kwargs = {
            "password": {"write_only": True},
        }

    def validate(self, attrs):
        errors = {}
        email = attrs.get("email")
        password = attrs.get("password")
        if self.instance:
            # Skip password validation on update
            if email and email != self.instance.email:
                if (
                    UserAccount.objects.filter(email=email)
                    .exclude(pk=self.instance.pk)
                    .exists()
                ):
                    errors["email"] = "A user with this email already exists."
        else:
            # Create validation
            if UserAccount.objects.filter(email=email).exists():
                errors["email"] = "A user with this email already exists."
            # Password validation only on create
            if password:
                try:
                    check_password_pattern_in_validation_serializers(password)
                except ValidationError as e:
                    errors["password"] = list(e.messages)

        if errors:
            raise serializers.ValidationError(errors)

        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password")
        phone_no = validated_data.get("phone_no")

        user = UserAccount.objects.create_user(
            email=validated_data["email"],
            full_name=validated_data["full_name"],
            phone_no=phone_no,
            password=password,
            is_active=validated_data.get("is_active", True),
            is_verified=validated_data.get("is_verified", True),
            is_admin=validated_data.get("is_admin", True),
            is_staff=validated_data.get("is_staff", True),
        )

        return user

    def update(self, instance, validated_data):
        # password is ignored here
        instance.email = validated_data.get("email", instance.email)
        instance.full_name = validated_data.get("full_name", instance.full_name)
        instance.phone_no = validated_data.get("phone_no", instance.phone_no)
        instance.is_active = validated_data.get("is_active", instance.is_active)
        instance.is_verified = validated_data.get("is_verified", instance.is_verified)
        instance.is_staff = validated_data.get("is_staff", instance.is_staff)
        instance.is_admin = validated_data.get("is_admin", instance.is_admin)

        instance.save()
        return instance


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = [
            "id",
            "bio",
            "profile_image",
            "social_auth_profile_link",
        ]


class AdminCustomerUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAccount
        fields = [
            "id",
            "full_name",
            "email",
            "phone_no",
            "date_of_birth",
            "is_active",
            "is_verified",
        ]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # user_profile = UserProfile.objects.filter(user=instance).first()
        data["profile_detail"] = UserProfileSerializer(instance).data
        return data
