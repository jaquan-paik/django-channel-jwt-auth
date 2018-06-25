import jwt, re
import traceback
from channels.auth import AuthMiddlewareStack
from django.contrib.auth.models import AnonymousUser
from django.conf import LazySettings
from jwt import InvalidSignatureError, ExpiredSignatureError, DecodeError
from urllib import parse

from .models import User
logger = logging.getLogger("test")
settings = LazySettings()

class TokenAuthMiddleware:
    def __init__(self, inner):
        self.inner = inner

    def __call__(self, scope):
        try:
            query = parse.parse_qs(scope['query_string'].decode("utf-8"))['token'][0]
            if query:
                try:
                    user_jwt = jwt.decode(
                        query,
                        settings.SECRET_KEY,
                    )
                    scope['user'] = User.objects.get(
                        id=user_jwt['user_id']
                    )
                except (InvalidSignatureError, KeyError, ExpiredSignatureError, DecodeError):
                    traceback.print_exc()
                    pass
                except Exception as e:  # NoQA
                    logger.error(scope)
                    traceback.print_exc()

            return self.inner(scope)
        except:
            scope['user']=AnonymousUser()
            return self.inner(scope)

TokenAuthMiddlewareStack = lambda inner: TokenAuthMiddleware(AuthMiddlewareStack(inner))
