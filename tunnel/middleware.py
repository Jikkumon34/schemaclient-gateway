from django.conf import settings


class TunnelSubdomainMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.get_host().split(":")[0].lower()
        request.tunnel_id = None

        base_domain = str(getattr(settings, "TUNNEL_BASE_DOMAIN", "")).strip().lower()
        if not base_domain:
            return self.get_response(request)

        suffix = f".{base_domain}"
        if host == base_domain:
            return self.get_response(request)

        if host.endswith(suffix):
            subdomain = host[: -len(suffix)]
            # Single-label subdomains map directly to tunnel IDs.
            if subdomain and "." not in subdomain:
                request.tunnel_id = subdomain

        return self.get_response(request)
