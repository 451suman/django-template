from django.urls import path

from logger.views import apilog_view

urlpatterns = [
    path("apilog/", apilog_view.APILoggerListView().as_view(), name="apilog_list"),
    path(
        "apilog/<int:pk>/",
        apilog_view.APILoggerListView().as_view(),
        name="apilog_detail",
    ),
]
