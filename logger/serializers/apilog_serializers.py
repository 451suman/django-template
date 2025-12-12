from rest_framework import serializers
import json

from logger.models.apilog_model import ApiLogModel


class ApiLogReadOnlySerializer(serializers.ModelSerializer):
    class Meta:
        model = ApiLogModel
        fields = "__all__"

    def to_representation(self, instance):
        # Call the parent's to_representation to get the raw data
        data = super().to_representation(instance)

        # Process the 'headers' field
        try:
            # Safely parse the JSON string into a dictionary
            data["headers"] = json.loads(data["headers"])
        except (json.JSONDecodeError, TypeError):
            # Handle cases where the string isn't valid JSON (e.g., empty string, malformed)
            data["headers"] = data["headers"]  # or some other default value

        # Process the 'response' field
        try:
            data["response"] = json.loads(data["response"])
        except (json.JSONDecodeError, TypeError):
            data["response"] = data["response"]
        try:
            data["body"] = json.loads(data["body"])
        except (json.JSONDecodeError, TypeError):
            data["body"] = data["body"]

        return data
