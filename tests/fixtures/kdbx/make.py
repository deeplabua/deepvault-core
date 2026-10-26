"""Makes the KDBX test files for the core's KeePass import (ADR-0008) with an implementation
that is not ours: pykeepass for KDBX 4, and the short KDBX 3.1 writer below (pycryptodomex).
Run once: `python3 -m venv /tmp/kp && /tmp/kp/bin/pip install pykeepass && /tmp/kp/bin/python make.py`.
Every password and secret here is made up."""
import gzip, hashlib, os, struct, uuid
from pykeepass import create_database, PyKeePass
from Cryptodome.Cipher import AES, Salsa20

HERE = os.path.dirname(os.path.abspath(__file__))
PASSWORD = "test-password-4"

def fill(kp):
    work = kp.add_group(kp.root_group, "Work")
    servers = kp.add_group(work, "Servers")
    github = kp.add_entry(work, "GitHub", "alex", "gh-Secret-1!", url="https://github.com/login",
                          notes="Personal account", tags=["dev", "code"], otp="otpauth://totp/GitHub:alex?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
    github.set_custom_property("Recovery code", "rc-1234-5678", protect=True)
    github.set_custom_property("Plan", "Pro")
    github.save_history()
    github.password = "gh-Secret-2!"   # the old one stays in History only
    kp.add_entry(servers, "db-1", "root", "Db!Root#9", url="ssh://db-1.example.com")
    kp.add_entry(kp.root_group, "Wi-Fi", "", "", notes="Network: Home\nKey: lantern-harbor")
    doc = kp.add_entry(kp.root_group, "Passport", "", "")
    binary = kp.add_binary(b"%PDF-1.4 made-up passport scan\x00\x01\x02", protected=True)
    doc.add_attachment(binary, "passport.pdf")
    trashed = kp.add_entry(kp.root_group, "Old forum", "me", "forum-pw")
    kp.trash_entry(trashed)
    return kp

def v4(name, cipher=None, kdf=None, keyfile=None):
    path = os.path.join(HERE, name)
    if os.path.exists(path):
        os.remove(path)
    kp = create_database(path, password=PASSWORD, keyfile=keyfile)
    header = kp.kdbx.header.value.dynamic_header
    if cipher:
        header.cipher_id.data = cipher
    if kdf:
        header.kdf_parameters.data.dict["$UUID"].value = kdf
    fill(kp).save()
    PyKeePass(path, password=PASSWORD, keyfile=keyfile)  # opens again

v4("v4-aes-argon2d.kdbx")
v4("v4-chacha20-argon2id.kdbx", cipher="chacha20", kdf=uuid.UUID("9e298b19-56db-4773-b23d-fc3ec6f0a1e6").bytes)
keyfile = os.path.join(HERE, "v4.keyx")
with open(keyfile, "w") as f:
    key = bytes(range(32))
    digest = hashlib.sha256(key).digest()[:4].hex().upper()
    hexkey = key.hex().upper()
    f.write('<?xml version="1.0" encoding="utf-8"?>\n<KeyFile><Meta><Version>2.0</Version></Meta><Key>'
            f'<Data Hash="{digest}">{" ".join(hexkey[i:i+8] for i in range(0, 64, 8))}</Data></Key></KeyFile>\n')
v4("v4-keyfile.kdbx", keyfile=keyfile)

# KDBX 3.1: AES-KDF, AES-256-CBC, gzip, hashed blocks, Salsa20 for protected values.
def v3(name):
    master_seed, transform_seed, iv = os.urandom(32), os.urandom(32), os.urandom(16)
    stream_key, start = os.urandom(32), os.urandom(32)
    rounds = 6000
    salsa = Salsa20.new(key=hashlib.sha256(stream_key).digest(), nonce=bytes.fromhex("E830094B97205D2A"))
    def protect(text):
        import base64
        data = text.encode()
        return base64.b64encode(bytes(a ^ b for a, b in zip(data, salsa.encrypt(bytes(len(data)))))).decode()
    xml = f"""<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile><Meta><Generator>make.py</Generator><RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID></Meta><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID><Name>Root</Name>
<Entry><UUID>AgICAgICAgICAgICAgICAg==</UUID><Tags>legacy</Tags>
<String><Key>Title</Key><Value>Old Mail</Value></String>
<String><Key>UserName</Key><Value>alex@example.com</Value></String>
<String><Key>Password</Key><Value Protected="True">{protect("mail-Pass-3!")}</Value></String>
<String><Key>URL</Key><Value>https://mail.example.com</Value></String>
<String><Key>Notes</Key><Value>From KeePass 2.x</Value></String>
</Entry></Group></Root></KeePassFile>"""
    payload = gzip.compress(xml.encode())
    blocks = struct.pack("<I", 0) + hashlib.sha256(payload).digest() + struct.pack("<I", len(payload)) + payload
    blocks += struct.pack("<I", 1) + bytes(32) + struct.pack("<I", 0)
    composite = hashlib.sha256(hashlib.sha256(PASSWORD.encode()).digest()).digest()
    transformed = composite
    ecb = AES.new(transform_seed, AES.MODE_ECB)
    for _ in range(rounds):
        transformed = ecb.encrypt(transformed)
    key = hashlib.sha256(master_seed + hashlib.sha256(transformed).digest()).digest()
    plain = start + blocks
    pad = 16 - len(plain) % 16
    body = AES.new(key, AES.MODE_CBC, iv).encrypt(plain + bytes([pad]) * pad)
    def field(kind, data):
        return struct.pack("<BH", kind, len(data)) + data
    header = struct.pack("<IIHH", 0x9AA2D903, 0xB54BFB67, 1, 3)
    header += field(2, uuid.UUID("31c1f2e6-bf71-4350-be58-05216afc5aff").bytes)
    header += field(3, struct.pack("<I", 1)) + field(4, master_seed) + field(5, transform_seed)
    header += field(6, struct.pack("<Q", rounds)) + field(7, iv) + field(8, stream_key) + field(9, start)
    header += field(10, struct.pack("<I", 2)) + field(0, b"\r\n\r\n")
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(header + body)
    PyKeePass(os.path.join(HERE, name), password=PASSWORD)  # pykeepass opens it: the writer is right

v3("v3-aes-kdf.kdbx")
print("ok")
