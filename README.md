# django-channel-jwt-auth
the jwt auth check and put user in scope

it check the query and get user.


for example : 

token={JWT}

'ws://localhost:8000/ws/chat/ROOM1/?token={JWT}

in routing.py


from .auth_token import TokenAuthMiddleware

application = ProtocolTypeRouter({
    "websocket": OriginValidator(
        TokenAuthMiddleware(
            URLRouter([
               //
            ])
        ),["*"]
    ),
})


# Jwt auth middleware

 we add this middleware to asgi.py file like this:

 django_asgi_app = get_asgi_application()

 application = ProtocolTypeRouter({
     "http": django_asgi_app,
     "websocket": JWTAuthMiddleware(URLRouter(
         your websocketurlpatterns
     ))
 })

and you can send a token from header 
