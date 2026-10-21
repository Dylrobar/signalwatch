"""Validated preview origins and JSON CORS diagnostics."""
import re
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

PREVIEW_ORIGINS = {"https://*.lovable.app", "https://*.lovableproject.com"}

class SignalWatchCORS(CORSMiddleware):
    def __init__(self, app, allow_origins=(), **kwargs):
        label = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
        patterns = [r"https://(?:" + label + r"\.)+" + re.escape(origin.removeprefix("https://*."))
                    for origin in allow_origins if origin in PREVIEW_ORIGINS]
        super().__init__(app, allow_origins=[o for o in allow_origins if o not in PREVIEW_ORIGINS],
                         allow_origin_regex="(?:" + "|".join(patterns) + ")" if patterns else None, **kwargs)

    def preflight_response(self, request_headers):
        response = super().preflight_response(request_headers)
        if response.status_code != 200:
            return JSONResponse({"error": "cors_denied", "detail": "Origin, method, or headers are not allowed by the CORS policy."},
                                status_code=403, headers={k: v for k, v in response.headers.items() if k not in {"content-length", "content-type"}})
        return response

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            from starlette.datastructures import Headers
            headers = Headers(scope=scope)
            origin = headers.get("origin")
            same_origin = origin == scope.get("scheme", "http") + "://" + headers.get("host", "")
            if origin and not same_origin and not self.is_allowed_origin(origin):
                response = JSONResponse({"error": "cors_origin_denied", "detail": "Origin is not allowed by SIGNALWATCH_CORS_ORIGINS."},
                                        status_code=403, headers={"Vary": "Origin"})
                await response(scope, receive, send)
                return
        await super().__call__(scope, receive, send)
