# Independent check of the .dvault v1 vector: pyca/cryptography (OpenSSL) + pure-Python HChaCha20.
# python3 tests/vectors/check_v1.py tests/vectors/v1_sample.json tests/fixtures/v1_sample.dvault
import hashlib, hmac, json, struct, sys
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

vec = json.load(open(sys.argv[1])); fixture = open(sys.argv[2], 'rb').read()
i, e = vec['input'], vec['expected']; h = bytes.fromhex

def rotl(v, c): return ((v << c) & 0xffffffff) | (v >> (32 - c))
def qr(s, a, b, c, d):
    s[a]=(s[a]+s[b])&0xffffffff; s[d]=rotl(s[d]^s[a],16)
    s[c]=(s[c]+s[d])&0xffffffff; s[b]=rotl(s[b]^s[c],12)
    s[a]=(s[a]+s[b])&0xffffffff; s[d]=rotl(s[d]^s[a],8)
    s[c]=(s[c]+s[d])&0xffffffff; s[b]=rotl(s[b]^s[c],7)
def hchacha20(key, nonce16):
    s = [0x61707865,0x3320646e,0x79622d32,0x6b206574] + list(struct.unpack('<8I', key)) + list(struct.unpack('<4I', nonce16))
    for _ in range(10):
        qr(s,0,4,8,12); qr(s,1,5,9,13); qr(s,2,6,10,14); qr(s,3,7,11,15)
        qr(s,0,5,10,15); qr(s,1,6,11,12); qr(s,2,7,8,13); qr(s,3,4,9,14)
    return struct.pack('<8I', *(s[0:4] + s[12:16]))
def xseal(key, nonce, pt, aad):
    return ChaCha20Poly1305(hchacha20(key, nonce[:16])).encrypt(b'\0'*4 + nonce[16:], pt, aad)
def aad(purpose, vid, extra): return b'DVLT' + struct.pack('<H', 1) + purpose + b'\0' + vid + extra

k = i['kdf']; vid = h(i['vault_id']); vk = h(i['vault_key'])
kek = Argon2id(salt=h(k['salt']), length=32, iterations=k['t'], lanes=k['p'], memory_cost=k['m_kib']).derive(i['password'].encode())
wrapped = xseal(kek, h(i['slot_nonce']), vk, aad(b'slot', vid, b'password'))
sub = {p: HKDF(hashes.SHA256(), 32, vid, b'deepvault/v1/' + p.encode()).derive(vk) for p in ('header-mac','file-mac','entries')}
ct = xseal(sub['entries'], h(i['entry_nonce']), h(e['entry_plaintext']), aad(b'entry', vid, h(i['entry_id'])))

checks = {
  'kek': kek.hex() == e['kek'],
  'wrapped_vault_key': wrapped.hex() == e['wrapped_vault_key'],
  'header_mac_key': sub['header-mac'].hex() == e['header_mac_key'],
  'file_mac_key': sub['file-mac'].hex() == e['file_mac_key'],
  'entries_key': sub['entries'].hex() == e['entries_key'],
  'entry_ciphertext': ct.hex() == e['entry_ciphertext'],
}
hl = struct.unpack('<I', fixture[6:10])[0]; hend = 10 + hl
checks['header_mac'] = hmac.new(sub['header-mac'], fixture[:hend], hashlib.sha256).digest() == fixture[hend:hend+32]
checks['file_mac'] = hmac.new(sub['file-mac'], fixture[:-32], hashlib.sha256).digest() == fixture[-32:]
checks['wrapped_vk_in_file'] = wrapped in fixture[10:hend]
checks['ciphertext_in_file'] = ct in fixture
for name, ok in checks.items(): print(('ok  ' if ok else 'FAIL'), name)
sys.exit(0 if all(checks.values()) else 1)
