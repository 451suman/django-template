from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination


class PagePagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100
    custom_message = "data retrieved successfully"

    def get_paginated_response(self, data):
        return Response(
            {
                "success": True,
                "message": self.custom_message,
                "data": data,  # keep naming consistent
                "pagination_info": {
                    "count": self.page.paginator.count,
                    "total_pages": self.page.paginator.num_pages,
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                },
            }
        )


# class PagePagination2(PageNumberPagination):
#     page_size = 10
#     page_size_query_param = "page_size"
#     max_page_size = 100
#     custom_message = "data retrieved successfully"

#     def get_paginated_response(self, data):
#         return Response(
#             {
#                 "success": True,
#                 "message": self.custom_message,
#                 "data": data,  # keep naming consistent
#                 "pagination_info": {
#                     "count": self.page.paginator.count,
#                     "total_pages": self.page.paginator.num_pages,
#                     "next": self.get_next_link(),
#                     "previous": self.get_previous_link(),
#                 },
#             }
#         )
