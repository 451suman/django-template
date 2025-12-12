from drf_yasg import openapi

# Define the common query parameter 'type'
common_type_param = openapi.Parameter(
    "type",
    openapi.IN_QUERY,
    description="Filter by type: event, voting, or all",
    type=openapi.TYPE_STRING,
    enum=["event", "voting", "all"],
    required=False,
)
