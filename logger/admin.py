from django.contrib import admin

from logger.models.apilog_model import ApiLogModel


@admin.register(ApiLogModel)
class APILoggerAdmin(admin.ModelAdmin):
    list_display = (
        "api",
        "method",
        "client_ip_address",
        "status_code",
    )
    list_filter = ("method", "client_ip_address", "api", "status_code")
    search_fields = ("method", "client_ip_address", "api", "status_code")
