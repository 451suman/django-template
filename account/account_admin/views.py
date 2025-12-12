from django.contrib.auth import get_user_model
from django.forms import ValidationError
from rest_framework import viewsets, filters
from rest_framework.permissions import IsAdminUser
from account.account_admin.serializers import (
    AdminCustomerUserSerializer,
    AdminUserSerializer,
)
from account.models import UserAccount
from common.response import error_response, success_response
from django.contrib.auth.password_validation import validate_password

from common.base_views import CRUDView

User = get_user_model()


class AdminUserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.filter(is_admin=True)
    serializer_class = AdminUserSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter]
    search_fields = ["email", "full_name"]
    # http_method_names = ["get", "post", "patch", "delete"]

    def list(self, request):
        try:
            queryset = self.filter_queryset(self.get_queryset())
        except Exception as e:
            return error_response(message="Failed to get admin list.", errors=str(e))
        serializer = self.get_serializer(queryset, many=True)
        return success_response(data=serializer.data, message="List of admin data")

    def retrieve(self, request, pk=None):
        try:
            queryset = self.get_queryset().get(id=pk)
            serializer = self.get_serializer(queryset)
            return success_response(data=serializer.data, message="Admin data")
        except User.DoesNotExist:
            return error_response(message="Admin not found.")

    def create(self, request):

        try:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return success_response(
                    data=serializer.data, message="Admin created successfully."
                )
            return error_response(
                message="Failed to create admin.", errors=serializer.errors
            )
        except ValidationError as e:
            return error_response(message="Invalid data.", errors=e.detail)
        except Exception as e:
            return error_response(message="Failed to create admin.", errors=str(e))

    def update(self, request, pk=None):
        return error_response(message="Method not allowed.", errors="MethodNotAllowed")

    def partial_update(self, request, pk=None):
        try:
            instance = self.get_queryset().get(id=pk)
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return success_response(
                    data=serializer.data, message="Admin updated successfully."
                )
            return error_response(
                message="Failed to update admin.", errors=serializer.errors
            )
        except User.DoesNotExist:
            return error_response(message="Admin not found.")
        except ValidationError as e:
            return error_response(message="Invalid data.", errors=e.detail)
        except Exception as e:
            return error_response(message="Failed to update admin.", errors=str(e))

    def destroy(self, request, pk):
        try:
            instance = self.get_queryset().get(id=pk)
            instance.delete()
            return success_response(message="Admin deleted successfully.")
        except User.DoesNotExist:
            return error_response(message="Admin not found.")
        except Exception as e:
            return error_response(message="Failed to delete admin.", errors=str(e))


class AdminCustomerUserViewSet(CRUDView):
    queryset = (
        UserAccount.objects.select_related("profile")
        .filter(is_admin=False)
        .order_by("-id")
    )
    serializer_class = AdminCustomerUserSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter]
    search_fields = ["email", "full_name", "phone_no"]
    http_method_names = ["get"]
    operation_name = "Customer"

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.filter_queryset(self.get_queryset())
            page = None
            if request.query_params.get("paginate", "").lower() == "true":
                page = self.paginate_queryset(queryset)
            # Handle paginated response
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            serializer = self.serializer_class(
                queryset, many=True, context={"request": request}
            )
            return success_response(
                serializer.data,
                message=f"{self.operation_name} list retrieved successfully",
            )
        except Exception as e:
            return error_response(
                message=f"{self.operation_name} error fetching data", errors=str(e)
            )
