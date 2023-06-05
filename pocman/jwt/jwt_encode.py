import jwt
encoded_jwt = jwt.encode({'user_name': 'adminsss'}, 'key')
print(encoded_jwt)
print(jwt.decode(encoded_jwt, 'key', algorithms=['HS256']))