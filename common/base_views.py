from drf_yasg.utils import swagger_auto_schema
from rest_framework import viewsets
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.permissions import DjangoModelPermissions
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAdminUser
from rest_framework import filters
from common.pagination import PagePagination
from common.response import error_response, success_response

from .swagger_parameters import common_type_param





class CRUDView(ModelViewSet):
    queryset = None
    serializer_class = None
    operation_name = None
    permission_classes = [IsAdminUser]
    http_method_names = ["get", "post", "patch", "delete"]
    filter_backends = [filters.SearchFilter]
    search_fields = ["id"]
    pagination_class = PagePagination

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

    def retrieve(self, request, pk=None):
        try:
            try:
                obj = self.get_queryset().get(pk=pk)
            except self.queryset.model.DoesNotExist:
                return error_response(message=f"{self.operation_name} not found")

            serializer = self.serializer_class(obj, context={"request": request})
            return success_response(
                serializer.data,
                message=f"{self.operation_name} retrieved successfully",
            )
        except Exception as e:
            return error_response(
                message=f"{self.operation_name} error retrieving data", errors=str(e)
            )

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request}
            )
            if serializer.is_valid():
                serializer.save()
                return success_response(
                    serializer.data,
                    message=f"{self.operation_name} created successfully",
                )
            return error_response(
                message=f"{self.operation_name} validation failed",
                errors=serializer.errors,
            )
        except Exception as e:
            return error_response(
                message=f"{self.operation_name} error creating", errors=str(e)
            )

    def partial_update(self, request, pk=None):
        try:
            try:
                obj = self.get_queryset().get(pk=pk)
            except self.queryset.model.DoesNotExist:
                return error_response(message=f"{self.operation_name} not found")

            serializer = self.serializer_class(
                obj, data=request.data, partial=True, context={"request": request}
            )
            if serializer.is_valid():
                serializer.save()
                return success_response(
                    serializer.data,
                    message=f"{self.operation_name} updated successfully",
                )
            return error_response(
                message=f"{self.operation_name} validation failed",
                errors=serializer.errors,
            )
        except Exception as e:
            return error_response(
                message=f"{self.operation_name} error updating", errors=str(e)
            )

    def update(self, request, pk=None):
        try:
            try:
                obj = self.get_queryset().get(pk=pk)
            except self.queryset.model.DoesNotExist:
                return error_response(message=f"{self.operation_name} not found")

            serializer = self.serializer_class(
                obj, data=request.data, context={"request": request}
            )
            if serializer.is_valid():
                serializer.save()
                return success_response(
                    serializer.data,
                    message=f"{self.operation_name} updated successfully",
                )
            return error_response(
                message=f"{self.operation_name} validation failed",
                errors=serializer.errors,
            )
        except Exception as e:
            return error_response(
                message=f"{self.operation_name} error updating", errors=str(e)
            )

    def destroy(self, request, pk=None):
        try:
            try:
                obj = self.get_queryset().get(pk=pk)
            except self.queryset.model.DoesNotExist:
                return error_response(message=f"{self.operation_name} not found")

            obj.delete()

            return success_response(
                message=f"{self.operation_name} deleted successfully",
                status=204,
            )
        except Exception as e:
            return error_response(
                message=f"{self.operation_name} error deleting", errors=str(e)
            )



class BaseAPIView(APIView):
    @swagger_auto_schema(manual_parameters=[common_type_param])
    def get(self, request, *args, **kwargs):
        """
        Default method for handling GET requests
        You can override this in your view.
        """
        return super().get(request, *args, **kwargs)


class BaseAPIViewSet(viewsets.ModelViewSet):
    """
    Base API ViewSet providing standardized CRUD operations.

    This class serves as a reusable foundation for implementing Create, Retrieve,
    Update, and Delete (CRUD) endpoints across various resources using Django REST Framework.

    Features:
    - Wraps all responses using custom `success_response` and `error_response` helpers
      to ensure consistent API output structure.
    - Centralized exception handling for:
        - `ValidationError` (invalid request data)
        - `NotFound` (resource not found)
        - Generic `Exception` for unexpected errors.
    - Uses the `operation_name` attribute to generate human-readable messages dynamically.
    - Applies `IsAuthenticated` permission by default (can be overridden by subclasses).

    Attributes:
    ----------
    queryset : QuerySet or None
        Must be defined in subclasses to specify the data set.
    serializer_class : Serializer or None
        Must be defined in subclasses to specify serialization logic.
    permission_classes : list
        List of permission classes (default: `[IsAuthenticated]`).
    operation_name : str or None
        Descriptive name of the resource managed by this ViewSet (e.g., "ticket", "user", e.g., "Got {ticket} successfully").

    Expected Response Structure:
    ----------------------------
    All responses have a consistent JSON format:
        {
            "success": true or false,
            "message": "Operation result description",
            "data": <response data on success>,
            "errors": <error details on failure>
        }

    Usage:
    ------
    Subclass this base ViewSet and configure the necessary attributes to implement
    standardized CRUD APIs.

    Example:
    --------
    class UserViewSet(BaseAdminAPIViewSet):
        queryset = User.objects.all()
        serializer_class = UserSerializer
        permission_classes = [IsAdminUser]
        operation_name = "user"
    """

    queryset = None
    serializer_class = None
    permission_classes = [DjangoModelPermissions]
    operation_name = None
    pagination_class = PagePagination

    def get_paginated_response(self, data):
        self.paginator.custom_message = f"Got {self.operation_name} successfully"
        return self.paginator.get_paginated_response(data)

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["request"] = self.request
        return context

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.filter_queryset(self.get_queryset())
            if not self.queryset.exists():
                raise NotFound(f"No {self.operation_name} found.")

            # response = super().list(request, *args, **kwargs)
            if request.query_params.get("pagination", "").lower() == "false":
                page = None
            else:
                page = self.paginate_queryset(queryset)

            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            return success_response(
                data=serializer.data,
                message=f"Got all {self.operation_name} successfully",
            )
        except NotFound as nf:
            return error_response(message=str(nf), status=404)
        except Exception as e:
            return error_response(message="An unexpected error occurred", errors=str(e))

    def retrieve(self, request, *args, **kwargs):
        try:
            response = super().retrieve(request, *args, **kwargs)
            return success_response(
                data=response.data,
                message=f"Fetched {self.operation_name} successfully",
            )
        except NotFound as nf:
            return error_response(message=str(nf), status=404)
        except Exception as e:
            return error_response(message="An unexpected error occurred", errors=str(e))

    def create(self, request, *args, **kwargs):
        try:
            response = super().create(request, *args, **kwargs)
            return success_response(
                data=response.data,
                message=f"Created {self.operation_name} successfully",
            )
        except ValidationError as ve:
            return error_response(message="Validation Failed", errors=ve.detail)
        except Exception as e:
            return error_response(message="An unexpected error occurred", errors=str(e))

    def update(self, request, *args, **kwargs):
        try:
            response = super().update(request, *args, **kwargs)
            return success_response(
                data=response.data,
                message=f"Updated {self.operation_name} successfully",
            )
        except ValidationError as ve:
            return error_response(message="Validation Failed", errors=ve.detail)
        except NotFound as nf:
            return error_response(message=str(nf), status=404)
        except Exception as e:
            return error_response(message="An unexpected error occurred", errors=str(e))

    def partial_update(self, request, *args, **kwargs):
        try:
            kwargs["partial"] = True
            return super().partial_update(request, *args, **kwargs)
        except ValidationError as ve:
            return error_response(message="Validation Failed", errors=ve.detail)
        except NotFound as nf:
            return error_response(message=str(nf), status=404)
        except Exception as e:
            return error_response(message="An unexpected error occurred", errors=str(e))

    def destroy(self, request, *args, **kwargs):
        try:
            super().destroy(request, *args, **kwargs)
            return success_response(
                message=f"Deleted {self.operation_name} successfully",
                status=200,
            )
        except NotFound as nf:
            return error_response(message=str(nf), status=404)
        except Exception as e:
            return error_response(message="An unexpected error occurred", errors=str(e))


