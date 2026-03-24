import struct
import zlib
import sys
import io

# Force UTF-8 output on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

def rc4(key, data):
    key = [ord(c) for c in key] if isinstance(key, str) else list(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

RC4_KEY = "CD&ML"

PACKET_TYPES = {0:'SYN', 1:'CONNECT', 2:'DATA', 3:'DISCONNECT', 4:'PING', 5:'NATPING'}
STREAM_TYPES = {1:'DO', 2:'RVAuthentication', 3:'RVSecure', 4:'SandBoxMgmt', 5:'NAT'}
FLAG_NAMES = {1:'ACK', 2:'RELIABLE', 4:'NEED_ACK', 8:'HAS_SIZE'}

def parse_vport(b):
    stream_type = (b >> 4) & 0xF
    port = b & 0xF
    return stream_type, port

def flags_str(flags):
    parts = []
    for bit, name in FLAG_NAMES.items():
        if flags & bit:
            parts.append(name)
    return '|'.join(parts) if parts else 'none'

def read_string(data, offset):
    if offset + 2 > len(data):
        return None, offset
    length = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    if length == 0:
        return '', offset
    if offset + length > len(data):
        s = data[offset:]
        return s.decode('ascii', errors='replace'), offset + len(s)
    s = data[offset:offset+length-1]  # exclude null terminator
    offset += length
    return s.decode('ascii', errors='replace'), offset

def parse_qrv(data):
    result = {}
    offset = 0
    if len(data) < 4:
        return result

    payload_size = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    result['payload_size'] = payload_size

    proto_name, offset = read_string(data, offset)
    result['proto_name'] = proto_name

    if offset >= len(data):
        return result

    pkt_type = data[offset]; offset += 1
    result['pkt_type_byte'] = pkt_type
    # 0=request, 1=response (typical NEX convention)

    if offset >= len(data):
        return result
    success = data[offset]; offset += 1
    result['success'] = success

    if offset + 4 > len(data):
        return result
    call_id = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    result['call_id'] = call_id

    method_name, offset = read_string(data, offset)
    result['method_name'] = method_name

    result['data_offset'] = offset
    result['remaining'] = data[offset:]
    return result

def hex_dump(data, indent="    "):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{x:02x}' for x in chunk)
        asc_part = ''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)
        print(f"{indent}{i:04x}: {hex_part:<48}  {asc_part}")

def parse_prudp_packet(name, hex_str, direction):
    print(f"\n{'='*70}")
    print(f"Packet {name} ({direction})")
    print(f"{'='*70}")

    raw = bytes.fromhex(hex_str)
    print(f"Raw ({len(raw)} bytes)")

    offset = 0
    src_vport = raw[offset]; offset += 1
    dst_vport = raw[offset]; offset += 1
    type_flags = raw[offset]; offset += 1
    session_id = raw[offset]; offset += 1
    signature = struct.unpack_from('<I', raw, offset)[0]; offset += 4
    seq_id = struct.unpack_from('<H', raw, offset)[0]; offset += 2

    src_stream, src_port = parse_vport(src_vport)
    dst_stream, dst_port = parse_vport(dst_vport)

    pkt_type = type_flags & 0x7
    flags = (type_flags >> 3) & 0x1F

    print(f"  src: stream={src_stream}/{STREAM_TYPES.get(src_stream,'?')} port={src_port}")
    print(f"  dst: stream={dst_stream}/{STREAM_TYPES.get(dst_stream,'?')} port={dst_port}")
    print(f"  type: {pkt_type} ({PACKET_TYPES.get(pkt_type,'?')}), flags: {flags} ({flags_str(flags)})")
    print(f"  session_id={session_id}, sig=0x{signature:08x}, seq_id={seq_id}")

    part_num = None
    if pkt_type == 2:
        part_num = raw[offset]; offset += 1
        print(f"  part_num: {part_num}")

    if flags & 8:
        payload_size_field = struct.unpack_from('<H', raw, offset)[0]; offset += 2
        print(f"  payload_size (header field): {payload_size_field}")

    if len(raw) > offset + 4:
        payload_enc = raw[offset:-4]
        checksum = raw[-4:]
    else:
        payload_enc = raw[offset:]
        checksum = b''

    print(f"  checksum: {checksum.hex() if checksum else 'n/a'}")
    print(f"  encrypted payload ({len(payload_enc)} bytes): {payload_enc.hex()[:80]}{'...' if len(payload_enc)>40 else ''}")

    if pkt_type != 2 or len(payload_enc) == 0:
        print("  [no DATA payload to decrypt]")
        return

    is_rvsecure = (src_stream == 3 or dst_stream == 3)
    if not is_rvsecure:
        print(f"  [stream is not RVSecure, skipping decryption]")
        return

    decrypted = rc4(RC4_KEY, payload_enc)
    print(f"  decrypted ({len(decrypted)} bytes): {decrypted.hex()[:80]}{'...' if len(decrypted)>40 else ''}")

    if len(decrypted) == 0:
        return

    comp_ratio = decrypted[0]
    payload_data = decrypted[1:]
    print(f"  compression_ratio byte: {comp_ratio}")

    if comp_ratio != 0:
        try:
            decompressed = zlib.decompress(payload_data)
            print(f"  [zlib decompressed: {len(payload_data)} -> {len(decompressed)} bytes]")
            payload_data = decompressed
        except Exception as e:
            print(f"  [zlib decompress failed: {e}]")
    else:
        print(f"  [uncompressed, {len(payload_data)} bytes]")

    print(f"\n  Full payload hex dump:")
    hex_dump(payload_data, "  ")
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload_data)
    print(f"  ASCII: {printable}")

    print(f"\n  --- QRV parse ---")
    qrv = parse_qrv(payload_data)
    for k, v in qrv.items():
        if k == 'remaining':
            print(f"    remaining ({len(v)} bytes):")
            hex_dump(v, "      ")
            printable2 = ''.join(chr(b) if 32 <= b < 127 else '.' for b in v)
            print(f"    ASCII: {printable2}")
        else:
            print(f"    {k}: {v!r}")

packets = [
    ("13", "313f72a42ae107e1010000ab000dffd8e0dd3fec70ceb2fd647186615ba70c74640d013085c6b7279e15cd109a29ee5a984c58db655ceaff81b4020a3297fbef6edd97e4a75bf1aae5e813b241d329c99841eadb73b269d5d962e8f76130d557d830410906123905eeeae1f9fbd93de3a228ae593f3b99e9d35c94f6e5056d308b37d13198d59af62f0c72cb5ab1412faf6561bcf5cf7c42ba0a2b900fad90f1c2c11596ea8c148d3b264fa704abb556898d683799fc6ca9152cb23c", "server->client (LoginWithToken_V2 response)"),
    ("15", "3f3172a42ae107e102000066000d0de8ff509ee9735f7dcd24ba11b83b6e2f5cdf10b3f2a1cc3c8e2fe7aee25f50e84d2aa5d83fc1b2d66aa12bc1efa7f6eff04f3b31fad1fa56c3f93f9fc696fde5b14d4c5c7f6f1e5f5c25e5c6c84e99ef8b2b4c71b6cf28fb0e87a6d7f02e93c4ead9a5d32b3edea87df47acb", "client->server"),
    ("17", "313f72a42ae107e10300008c000dffd820d3bfc37de83a76a3fb4e9c80fbbab94e9a4e3bba1a43e2e51a86e6af7e461e2ef3a7b8e3e2fe8aca24fef1aa8d15c46a47e7e4c22e4f8ddc5e41faaedafd1ce4ae3e98a62f8ca6a1abf6ef4b04dab2f0fcf3d27a31f2bab3c1b", "server->client"),
    ("19", "3f3172a42ae107e104000041000d0d00d2be97fff9b327d1d4ee0bc476e6b8e9bcd8a7b76a86f7acfbaabb62bc84f62f0f0b66c92aa20aac2e8ba7765c7eb7ff92f2c3ec8ee9c3f8d2d2f8aed3a97f6df7c5d9afa9d2c4dc82f0b55c", "client->server"),
    ("21", "313f72a42ae107e10500024f000dffd8a8af93ee0c2e4e46f6a46ad40ed9fe9b14c8e3af8a94e28ea63cdebfaf843f77e48bce3f8be9e5e4fe8e9aeecfb0f5d3da93c0c7b4c8efcaeecae6cbc7b2b3ca93e3e2bababcc0b7bacee2c0a8b1d0b4b8d1baecabcae6c9b8c9c7bab7c2cbadc4cabcc3c9c8d3b6ccd5c0b5c7d0b8bfcac9bcc3d3b2c8d7bbbcc9c2b9bfcdd8b6c9d2b7bdb7cebebac7b9c4c9c8e5b5cbc8b6b8c6cdb9bccbd0b7c8d3b8b7c9c1bab0cdd9b6b8cbb7bac6cebbb0ccd7b7b7cec3b8b5cac8bbbccdcfb6bdd2b8b4c9c1b7b0cac8b4bfcbc8b4bfccc7b3becbc5b4bdc9c4b2bbccc7b4b8c9c3b0beccc6b4bdcbc0b3bdc9c5b1bfcbc6b4beccc5b4bbc9c4b3bacbc9b4beccc4b5bcc9c3b4bbcbc4b4bbc8c3b3bcccc3b4b9c8c3b4b9ccc2b5b9cbc3b5baccc0b2bacbc2b5b9ccc4b4b9c9c5b5baccc5b3b8cbc3b6baccc4b3b9cac0b3bfccc2b3bdc9c0b5becbc5b4beccc3b3bdc9c2b6beccc1b4bec9c5b5beccc1b4bdc8c5b6bfccc4b5bdc8c2b6c0ccc4b4bfc8c3b5c0cdc2b5bcc8c3b6bfcdb3b3bfccc3b4b9c9c1b3b9cac1b3b9ccc4b4b9ccc4b5b9c9c5b5baccc5b3b7cac0b3bfccc3b3bdc8c3b5beccc3b3bec9c3b4beccc2b4bcc9c2b5bfcac5b6beccc0b3bec9c3b6beccc1b3bec9c2b6bfcdc0b3bfc8c3b6c1ccc2b3bec8c4b6c0cdc4b4bec8c4b5bfcdb0b4bcca", "server->client (large fragment 1)"),
    ("22", "313f72a42ae107e106000088000dffd8b4becc5b4c0cac4b6bfccc4b4bec8c4b5bfcdb0b4bccab4bfccc4b4bec8c4b5bfcdb0", "server->client (fragment 2)"),
    ("45", "3f3172a42ae107e108000052000d0de897bee0b2f3e4c8b5b4bdf1d3a4c6e8e0e6edd9c5be8edcc5d5d7cbbfa8c3d5d4cbbea3d1c8d7cfbba8ced0cdd4c4b9a5cad4d0c1b5a0cfc5d3c7c2b2a5cdd3cbb3b9a5cdd5cbb7bfaacdd7c9b3b7afcdd5ccb7ba", "client->server"),
    ("46", "3f3172a42ae107e10900004d000d0de889b3e5b4f1e4cbbaafbeeed9a9cbeae2e7ecd9c8b78acdc1d3d4c9c3a7c2d4d3cac1a2d1c9d5cfc4a6cdd3d0c4b0a2cec4d1c8c2b2a5cdd3cbb3b9a5cdd5cbb7bf", "client->server"),
    ("47", "3f3172a42ae107e10a00004d000d0de89fb3e0b0f2e4cbbbaebeeed8a8caeae1e7ecd8c8b78bcdc0d2d5c8c3a8c2d4d2cac1a2d1c8d5cec4a6cdd2d0c4b0a2cec3d1c8c2b2a6cdd4cbb4b8a4cdd4ccb8be", "client->server"),
    ("48", "3f3172a42ae107e10b000092000d0de87eb5e5b4f8eecdb7b3c3f1d8a0ceede6ecf4d8c4bb87d3c7d9d8d5d0a5cad7d7d2d1a2d7ced9d6c1a4d2d3d5d4cab9a6d5d8d7d4c5bca5d2d3d0d3c9baa7d0d7d0d7c6bba5d2d7d3d4c3b8a5d3d8cfd7c4b9a8d1d4d3d6c2baaad2d7d2d8c4b9aad3d8d4d8c3b8a9d2d3d4d9c5bca7d2d8d0d7c2b8a9d4d8d4d7c4b7a9d3d9d0d5c1b8aad5dad0d7c3b8a8d2d4d2d7c3b8aad4d9d2d7c3b6abd5d8d1d9c5b7a8d3d4d3d8c5b9a8d3d6d3", "client->server"),
    ("53", "313f72a42ae107e11000007f000dffd800d53fec70c1b23369b28a6f286838f2a503093083c67076c74a124b9a27bb51b561e954889dc1e2c9167cb6a7509154e5da4fc6cd5ef727f9925992410bf6bd3ec40c18d5358eac4f204d67caefcea8233651f599169da7fc0af622e35ce3926116edb4e904b0de32f3bcd90d2e2a1382383ee970c4423e3e518600e12754c7", "server->client"),
    ("62", "313f72a42ae107e11100007a000dffd840de3fec70c9b2316973806b2265c8bce9c7c2fd8ec5732ac44a1a680ee22e0626b6fefe3bce6dbb6b33664fc562b23b713fabe2c7d55370572cbd7ef1b784dab47a1722e814f1cdcf2f74b3b8d58298de32eaf187828d013e88da0a8c1c7415aa8038f7b1edd44a754a2a7fcf9bdf86668ef1343e3a3b690d8947", "server->client"),
    ("64", "313f72a42ae107e11200003d000dffd8a8749f4c406052a8b264da3b1db57a2f39585d8ad67526fac945bb206e62788f6eb30eaf179ea186e477f1a140a5105793a2a3adc112f90d8c16c6514bee", "server->client"),
    ("74", "313f72a42ae107e11400005f000dffd8ec4b4c3e27c68218da35bfee00e523085ad55046d1e3bc96e24c07b571505427c28fa2e2c89ff6afb4af14dfb5a540d4d9e6e8f2b78aec42e87e6dd958e1c6c71ca6bcecfffe2a8afaef0c97d838e7", "server->client"),
    ("76", "313f72a42ae107e11500005f000dffd8ec4b4c3e278482aedc37bfee00df23085ad56042d3e3bc96e24c07b571505527c28fa2e2c89ff6afb4af14dfb5a540d4d9e6e8f2b78aec42e87e6dd958e1c6c71ca6bcecfffe2a8afaef0c97d838e7", "server->client"),
    ("78", "313f72a42ae107e11600005f000dffd8ec4b4c3e276c82c2db36bfee00dd23085ad56045d3e3bc96e24c07b571505627c28fa2e2c89ff6afb4af14dfb5a540d4d9e6e8f2b78aec42e87e6dd958e1c6c71ca6bcecfffe2a8afaef0c97d838e7", "server->client"),
    ("81", "313f72a42ae107e11700006c000dffd8ec4b4c3e271082f6db36bfee00db23085ad56048d3e3bc96e24c07b571505727c28fa2e2c89ff6afb4af14dfb5a540d4d9e6e8f2b78aec42e87e6dd958e1c6c71ca6bcecfffe2a8afaef0c97d838e7c6c58f21ca20c77b6c", "server->client"),
]

for name, hex_str, direction in packets:
    parse_prudp_packet(name, hex_str, direction)
