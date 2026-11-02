# Independent check of the format v2 vectors (ADR-0014): pyca/cryptography (OpenSSL) + pure-Python
# HChaCha20 and a minimal CBOR reader. Reads the package itself: decrypts the entry from the vault
# file, takes each file's key from the entry's `file` field, opens files/<id> chunk by chunk.
# python3 tests/vectors/check_v2.py tests/vectors/v2_sample.json tests/vectors/v2_sample.dvault [tests/vectors/file_v1.json]
import hashlib, hmac, json, os, struct, sys
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

vec = json.load(open(sys.argv[1])); package = sys.argv[2]
file_vec = json.load(open(sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.dirname(sys.argv[1]), 'file_v1.json')))
h = bytes.fromhex

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
def xseal(key, nonce, pt, aad): return ChaCha20Poly1305(hchacha20(key, nonce[:16])).encrypt(b'\0'*4 + nonce[16:], pt, aad)
def xopen(key, nonce, ct, aad): return ChaCha20Poly1305(hchacha20(key, nonce[:16])).decrypt(b'\0'*4 + nonce[16:], ct, aad)
def aad(version, purpose, vid, extra): return b'DVLT' + struct.pack('<H', version) + purpose + b'\0' + vid + extra

def cbor(data, at=0):
    """(value, next offset) for the CBOR DeepVault writes: uints, byte and text strings, arrays, maps, booleans."""
    ib = data[at]; major, info = ib >> 5, ib & 31; at += 1
    if major == 7: return {20: False, 21: True}[info], at
    if info < 24: n = info
    else:
        size = {24: 1, 25: 2, 26: 4, 27: 8}[info]; n = int.from_bytes(data[at:at+size], 'big'); at += size
    if major == 0: return n, at
    if major == 2: return data[at:at+n], at + n
    if major == 3: return data[at:at+n].decode(), at + n
    if major == 4:
        out = []
        for _ in range(n): v, at = cbor(data, at); out.append(v)
        return out, at
    if major == 5:
        out = {}
        for _ in range(n): k, at = cbor(data, at); v, at = cbor(data, at); out[k] = v
        return out, at
    raise ValueError('CBOR type %d' % major)
def cbor_one(data):
    value, end = cbor(data); assert end == len(data), 'bytes after the CBOR item'; return value

def chunk_nonce(prefix, i, last): return prefix + struct.pack('>I', i) + bytes([1 if last else 0])
def seal_file(vid, fid, key, prefix, chunk_size, content):
    parts = [content[i:i+chunk_size] for i in range(0, len(content), chunk_size)] or [b'']
    header = b'DVLF' + struct.pack('<H', 1) + fid + struct.pack('<I', chunk_size) + prefix
    chunks = [xseal(key, chunk_nonce(prefix, i, i == len(parts) - 1), p, aad(2, b'file', vid, fid)) for i, p in enumerate(parts)]
    return header, chunks
def open_file(ref, data):
    assert data[:4] == b'DVLF' and struct.unpack('<H', data[4:6])[0] == 1 and data[6:22] == ref['id']
    chunk_size = struct.unpack('<I', data[22:26])[0]; prefix = data[26:45]; body = data[45:]
    sealed = chunk_size + 16; parts = [body[i:i+sealed] for i in range(0, len(body), sealed)]
    content = b''.join(xopen(ref['key'], chunk_nonce(prefix, i, i == len(parts) - 1), p, aad(2, b'file', ref['vault'], ref['id']))
                       for i, p in enumerate(parts))
    return content

checks = {}

# One file.
fi, fe = file_vec['input'], file_vec['expected']
header, chunks = seal_file(h(fi['vault_id']), h(fi['file_id']), h(fi['key']), h(fi['nonce_prefix']), fi['chunk_size'], h(fi['content']))
checks['file: header'] = header.hex() == fe['header']
checks['file: chunks'] = [c.hex() for c in chunks] == fe['chunks']
checks['file: bytes'] = (header + b''.join(chunks)).hex() == fe['file']
checks['file: sha256'] = hashlib.sha256(h(fi['content'])).hexdigest() == fe['sha256']
ref = cbor_one(h(fe['field_value']))
checks['file: field value'] = (ref['id'] == h(fi['file_id']) and ref['vault'] == h(fi['vault_id']) and ref['key'] == h(fi['key'])
    and ref['name'] == fi['name'] and ref['size'] == len(h(fi['content'])) and ref['sha256'].hex() == fe['sha256'] and ref['created'] == fi['now']
    and list(ref) == ['id', 'vault', 'name', 'size', 'key', 'sha256', 'created'])

# The package.
i, e = vec['input'], vec['expected']
k = i['kdf']; vid = h(i['vault_id']); vk = h(i['vault_key'])
kek = Argon2id(salt=h(k['salt']), length=32, iterations=k['t'], lanes=k['p'], memory_cost=k['m_kib']).derive(i['password'].encode())
sub = {p: HKDF(hashes.SHA256(), 32, vid, b'deepvault/v1/' + p.encode()).derive(vk) for p in ('header-mac', 'file-mac', 'entries')}
sub['pack-mac'] = HKDF(hashes.SHA256(), 32, vid, b'deepvault/v2/pack-mac').derive(vk)
wrapped = xseal(kek, h(i['slot_nonce']), vk, aad(1, b'slot', vid, b'password'))
checks['kek'] = kek.hex() == e['kek']
checks['slot (AAD version 1)'] = wrapped.hex() == e['wrapped_vault_key']
for name, key in (('header_mac_key', 'header-mac'), ('file_mac_key', 'file-mac'), ('entries_key', 'entries'), ('pack_mac_key', 'pack-mac')):
    checks[name] = sub[key].hex() == e[name]

main = open(os.path.join(package, 'vault'), 'rb').read()
checks['vault: magic, version 2'] = main[:4] == b'DVLT' and struct.unpack('<H', main[4:6])[0] == 2
hl = struct.unpack('<I', main[6:10])[0]; hend = 10 + hl
checks['vault: header_mac'] = hmac.new(sub['header-mac'], main[:hend], hashlib.sha256).digest() == main[hend:hend+32]
checks['vault: file_mac'] = hmac.new(sub['file-mac'], main[:-32], hashlib.sha256).digest() == main[-32:]
checks['vault: slot in header'] = wrapped in main[10:hend]
at = hend + 32; count = struct.unpack('<I', main[at:at+4])[0]; at += 4
blocks = []
for _ in range(count):
    eid, nonce = main[at:at+16], main[at+16:at+40]; n = struct.unpack('<I', main[at+40:at+44])[0]
    blocks.append((eid, nonce, main[at+44:at+44+n])); at += 44 + n
checks['vault: one block, then the MAC'] = count == 1 and at == len(main) - 32
eid, nonce, ct = blocks[0]
checks['entry: ciphertext'] = ct.hex() == e['entry_ciphertext'] and eid == h(i['entry_id'])
plain = xopen(sub['entries'], nonce, ct, aad(2, b'entry', vid, eid))
checks['entry: plaintext (AAD version 2)'] = plain.hex() == e['entry_plaintext']
entry = cbor_one(plain)
refs = [cbor_one(f['value']) for f in entry['fields'] if f['name'] == 'file' and f['concealed']]
checks['entry: two file fields'] = len(refs) == 2 and entry['title'] == 'Example'
for n, (ref, given, listed) in enumerate(zip(refs, i['files'], e['files'])):
    data = open(os.path.join(package, 'files', ref['id'].hex()), 'rb').read()
    content = open_file(ref, data)
    header, chunks = seal_file(vid, h(given['file_id']), h(given['key']), h(given['nonce_prefix']), given['chunk_size'], h(given['content']))
    checks['file %d: content' % n] = content == h(given['content']) and ref['size'] == len(content)
    checks['file %d: sha256' % n] = hashlib.sha256(content).digest() == ref['sha256'] and ref['sha256'].hex() == listed['sha256']
    checks['file %d: bytes recreated' % n] = header + b''.join(chunks) == data and len(data) == listed['len']
checks['file 1 ends on a chunk boundary'] = len(h(i['files'][1]['content'])) % i['files'][1]['chunk_size'] == 0

for name, ok in checks.items(): print(('ok  ' if ok else 'FAIL'), name)
sys.exit(0 if all(checks.values()) else 1)
