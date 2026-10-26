"""Makes `v4-passkey.kdbx`: a KeePassXC passkey (its `KPEX_PASSKEY_*` strings, the key as a PKCS#8
PEM written by `cryptography`) in a pykeepass file, for the core's KeePass passkey import
(ADR-0010). Run once, like make.py: `/tmp/kp/bin/pip install pykeepass cryptography &&
/tmp/kp/bin/python passkey.py`. The key is made up: the scalar 0x11…11."""
import base64, os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pykeepass import create_database

HERE = os.path.dirname(os.path.abspath(__file__))
PASSWORD = "test-password-4"
SCALAR = int("11" * 32, 16)

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

key = ec.derive_private_key(SCALAR, ec.SECP256R1())
pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
path = os.path.join(HERE, "v4-passkey.kdbx")
if os.path.exists(path):
    os.remove(path)
kp = create_database(path, password=PASSWORD)
entry = kp.add_entry(kp.root_group, "webauthn.io", "pass_test", "", url="https://webauthn.io")
entry.set_custom_property("KPEX_PASSKEY_RELYING_PARTY", "webauthn.io")
entry.set_custom_property("KPEX_PASSKEY_USERNAME", "pass_test")
entry.set_custom_property("KPEX_PASSKEY_CREDENTIAL_ID", b64url(bytes(range(16))), protect=True)
entry.set_custom_property("KPEX_PASSKEY_USER_HANDLE", b64url(b"user-handle-1"), protect=True)
entry.set_custom_property("KPEX_PASSKEY_PRIVATE_KEY_PEM", pem, protect=True)
kp.save()
print("ok")
