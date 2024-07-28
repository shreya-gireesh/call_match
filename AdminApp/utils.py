import hmac
import hashlib
import base64
import time
import random
from django.conf import settings


def generate_agora_token(channel_name, uid, role, expiration_time_in_seconds=3600):
    current_time = int(time.time())
    privilege_expired_ts = current_time + expiration_time_in_seconds

    app_id = settings.AGORA_APP_ID
    app_certificate = settings.AGORA_APP_CERTIFICATE

    content = f"{app_id}{channel_name}{uid}{role}{privilege_expired_ts}".encode('utf-8')
    signature = hmac.new(app_certificate.encode('utf-8'), content, hashlib.sha256).digest()
    signature = base64.b64encode(signature).decode('utf-8')

    token = f"007eJxTYAjNbylZC4/Zz91Jk3E5ua3fU4U3Or7x3L2KUkb3Tc/iFRjaqEpjZKQYlGYUpySklCmWJmYkGChbJJTkpJZnJKZmRsamlmaFqZ4MpJJkNkFkciCwMCANx5yUkJTi0sjGDAwANgvIQw=="
    return token
