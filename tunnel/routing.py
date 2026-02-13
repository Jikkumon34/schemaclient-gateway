from django.urls import re_path

from .consumers import TunnelConsumer

websocket_urlpatterns = [
    re_path(r"^ws/tunnel/(?P<tunnel_id>[a-z0-9-]+)/$", TunnelConsumer.as_asgi()),
]
