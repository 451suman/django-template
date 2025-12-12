COUNTRY_CHOICE = [("NEPAL", "NEPAL")]

PAYMENT_GATEWAY_CHOICES = [
    ("NCHL", "NCHL"),
    ("MyPay", "MyPay"),
    ("CyberSource", "CyberSource"),
    ("FonePay", "FonePay"),
    ("Stripe", "Stripe"),
    ("", "No payment Gateway chosen"),
]

ORDER_STATUS = [
    ("Pending", "Pending"),
    ("Received", "Received"),
    ("Packaged", "Packaged"),
    ("Sent", "Sent"),
    ("Delivered", "Delivered"),
    ("Cancelled", "Cancelled"),
]

PAYMENT_STATUS = [
    ("pending", "Pending"),
    ("processing", "Processing"),
    ("completed", "Completed"),
    ("cancelled", "Cancelled"),
    ("failed", "Failed"),
    ("incomplete", "Incomplete"),
]

PAYMENT_METHOD_CHOICES = [
    ("DynamicQR", "Dynamic QR"),
    ("MyPayWallet", "MyPay Wallet"),
    ("Debit/CreditCards", "Debit/Credit Cards"),
    ("CashOnDelivery", "CashOnDelivery"),
    ("", "No payment method chosen"),
]


BANNER_APP_CHOICES = [
    ("sports", "Sports"),
    ("ecommerce", "Ecommerce"),
]
BANNER_DIRECTION_CHOICES = [
    ("mobile-horizontal", "Mobile Horizontal"),
    ("web-vertical", "Web Vertical"),
]
BANNER_TYPE_CHOICE = [
    ("image", "Image"),
    ("video", "Video"),
]


BANNER_TYPE_CHOICES = [
    ("individual", "Individual"),
    ("multiple", "Multiple"),
    ("external-redirect", "External Redirect"),
]


DEVICE_TYPES = [
    ("mobile", "Mobile"),
    ("web", "Web"),
]


VIEW_TYPE = [
    ("dashboard", "Dashboard"),
    ("global", "Global"),
    ("page 1", "Page 1"),
    ("page 2", "Page 2"),
    ("page 3", "Page 3"),
    ("page 4", "Page 4"),
]
