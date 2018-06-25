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

