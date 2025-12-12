from rest_framework.views import APIView
from rest_framework import permissions
from common.pagination import PagePagination
from common.response import error_response, success_response

from logger.models.apilog_model import ApiLogModel
from logger.serializers.apilog_serializers import ApiLogReadOnlySerializer


class APILoggerListView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request, pk=None):
        if pk is not None:
            try:
                api_log = ApiLogModel.objects.get(id=pk)
                serializer = ApiLogReadOnlySerializer(api_log)
                return success_response(
                    data=serializer.data, message="Got all API Log successfully"
                )
            except ApiLogModel.DoesNotExist:
                return error_response(
                    message="Requested ID for queryset doesn't exist",
                    errors={"id": [f"Requested ID : {pk}, doesn't exist"]},
                    status=404,
                )
        queryset = ApiLogModel.objects.all().order_by("-id")

        paginator = PagePagination()
        page = paginator.paginate_queryset(queryset, request)

        if page is not None:
            print("entered page not none")
            serializer = ApiLogReadOnlySerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)
        serializer = ApiLogReadOnlySerializer(queryset, many=True)
        return success_response(
            data=serializer.data, message="Got all API Log successfully"
        )
