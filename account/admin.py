from django.contrib import admin

# Register your models here.
from .models import UserAccount, LoginAttempt, UserProfile

admin.site.register(UserAccount)
admin.site.register(LoginAttempt)
# admin.site.register(UserProfile)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "social_auth_profile_link")
    search_fields = (
        "user__email",
        "user__full_name",
    )
