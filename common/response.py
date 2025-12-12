from rest_framework.response import Response


def success_response(data=None, extras=None, message="Success", status=200):
    if extras:
        return Response(
            {
                "success": True,
                "message": message,
                "data": data,
                extras["name"]: extras["extra_datas"],
            },
            status=status,
        )
    return Response({"success": True, "message": message, "data": data}, status=status)


def error_response(message="Error", errors=None, status=400):
    return Response(
        {"success": False, "message": message, "data": [], "errors": errors},
        status=status,
    )
