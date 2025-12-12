from django.db import models
from logger.utils import db_log_enabled
from django.contrib.auth import get_user_model

User = get_user_model()

if db_log_enabled():
    """
    Load conditionally based on settings to avoid unnecessay model registration
    """

    class BaseModel(models.Model):
        """Abstract base model for all logging related stuff"""

        id = models.BigAutoField(primary_key=True)
        added_on = models.DateField()

        def __str__(self):
            return str(self.id)

        class Meta:
            abstract = True
            ordering = "-added_on"

    class ApiLogModel(BaseModel):
        api = models.CharField(max_length=1024, help_text="API URL")
        headers = models.TextField()
        body = models.TextField()
        method = models.CharField(max_length=10, db_index=True)
        client_ip_address = models.CharField(max_length=50)
        response = models.TextField()
        status_code = models.SmallIntegerField(
            help_text="Response status code", db_index=True
        )
        execution_time = models.DecimalField(max_digits=8, decimal_places=3)
        user = models.ForeignKey(
            User, null=True, blank=True, on_delete=models.DO_NOTHING
        )

        def __str__(self):
            return self.api

        class Meta:
            db_table = "api_log"
            verbose_name = "API Log"
            verbose_name_plural = "API Logs"
