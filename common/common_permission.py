from rest_framework import permissions
from rest_framework.permissions import SAFE_METHODS, BasePermission


class IsMerchantPermission(BasePermission):
    """
    Custom permission to allow only specific users to list objects.
    """

    def has_permission(self, request, view):
        if request.method.lower() == "get":
            return request.user and hasattr(request.user, "merchant")

        return False


class IsAdminAndMerchantPermission(permissions.BasePermission):
    def __init__(self):
        self.default_perms = permissions.DjangoModelPermissions()
        # self.staff_perms = StaffDjangoModelPermissions()

    def check_get_pernisson(self, request, view):
        model_cls = getattr(getattr(view, "queryset", None), "model", None)
        if model_cls:
            app_label = model_cls._meta.app_label
            model_name = model_cls._meta.model_name
            perm_string = f"{app_label}.view_{model_name}"
            permis = request.user.get_all_permissions()
            if perm_string not in permis:
                return False
            return True

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False

        is_superuser = user.is_superuser
        is_staff = user.is_staff and not user.is_superuser
        is_merchant = getattr(user, "is_merchant", False) and hasattr(user, "merchant")

        if is_superuser:
            return self.default_perms.has_permission(request, view)

        if is_staff:
            if request.method in permissions.SAFE_METHODS:
                return self.check_get_pernisson(request, view)
            return self.default_perms.has_permission(request, view)

        if is_merchant:
            if request.method in permissions.SAFE_METHODS:
                return True
            return False

        return False

    def has_object_permission(self, request, view, obj):
        user = request.user
        if not user or not user.is_authenticated:
            return False

        is_superuser = user.is_superuser
        is_staff = (
            user.is_staff and not user.is_superuser
        )  # So staff doesn’t duplicate superuser logic
        is_merchant = getattr(user, "is_merchant", False) and hasattr(user, "merchant")

        if is_superuser:
            return self.default_perms.has_permission(request, view)

        if is_staff:
            if request.method in permissions.SAFE_METHODS:
                return self.check_get_pernisson(request, view)
            return self.default_perms.has_permission(request, view)

        if is_merchant:
            if request.method in permissions.SAFE_METHODS:
                return True
            return False
        return False
