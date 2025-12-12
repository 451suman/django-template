from django.urls import path
from rest_framework.routers import DefaultRouter
from account.account_admin import views

router = DefaultRouter()
router.register(r"user-admin", views.AdminUserViewSet, basename="admin_user_admin")
router.register(
    r"user-customer", views.AdminCustomerUserViewSet, basename="admin_user_customer"
)
urlpatterns = []
urlpatterns += router.urls
