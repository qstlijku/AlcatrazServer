#!/usr/bin/env python3
"""
Watch Dogs 1 PRUDP V0 packet decryptor/analyzer.
Key: "CD&ML", protocol: PRUDP V0 over UDP, QRV/RMC framing.
"""

import struct
import zlib

# ── RC4 ──────────────────────────────────────────────────────────────────────

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

# ── Constants ─────────────────────────────────────────────────────────────────

PACKET_TYPES = {0:'SYN', 1:'CONNECT', 2:'DATA', 3:'DISCONNECT', 4:'PING', 5:'NATPING'}
STREAM_TYPES = {1:'DO', 2:'RVAuthentication', 3:'RVSecure', 4:'SandBoxMgmt', 5:'NAT'}
# Flags: bits in the top 5 bits of byte 2 (shifted right by 3)
FLAG_BITS = {1:'ACK', 2:'RELIABLE', 4:'NEED_ACK', 8:'HAS_SIZE'}

# ── PRUDP V0 parser ──────────────────────────────────────────────────────────

def parse_prudp(data: bytes) -> dict:
    if len(data) < 10:
        raise ValueError("Packet too short")
    src_vport = data[0]
    dst_vport = data[1]
    src_stream = (src_vport >> 4) & 0xF
    src_port   = src_vport & 0xF
    dst_stream = (dst_vport >> 4) & 0xF
    dst_port   = dst_vport & 0xF

    type_flags  = data[2]
    pkt_type    = type_flags & 0x07
    flags_raw   = (type_flags >> 3) & 0x1F
    flag_names  = [name for bit, name in FLAG_BITS.items() if flags_raw & bit]

    session_id  = data[3]
    signature   = struct.unpack_from('<I', data, 4)[0]
    seq_id      = struct.unpack_from('<H', data, 8)[0]

    offset = 10
    part_number = None
    if pkt_type == 2:   # DATA
        part_number = data[offset]
        offset += 1

    payload_size_field = None
    if flags_raw & 8:   # HAS_SIZE
        payload_size_field = struct.unpack_from('<H', data, offset)[0]
        offset += 2

    checksum = struct.unpack_from('<I', data, len(data)-4)[0]
    payload  = data[offset:len(data)-4]

    return {
        'src_vport': src_vport,  'dst_vport': dst_vport,
        'src_stream': src_stream, 'src_port': src_port,
        'dst_stream': dst_stream, 'dst_port': dst_port,
        'pkt_type': pkt_type, 'pkt_type_name': PACKET_TYPES.get(pkt_type, f'UNK{pkt_type}'),
        'flags_raw': flags_raw,   'flag_names': flag_names,
        'session_id': session_id, 'signature': signature, 'seq_id': seq_id,
        'part_number': part_number, 'payload_size_field': payload_size_field,
        'payload': payload, 'checksum': checksum,
    }

# ── QRV / RMC parser ─────────────────────────────────────────────────────────

# Known protocol names and method IDs (NEX / Rendez-Vous)
KNOWN_PROTOCOLS = {
    'Authentication': {1: 'Login', 2: 'LoginEx', 3: 'RequestTicket', 4: 'GetPID',
                       5: 'GetName', 6: 'LoginWithParam', 100: 'LoginWithToken',
                       101: 'LoginWithTokenV2'},
    'SecureConnection': {1: 'Register', 2: 'RequestConnectionData', 3: 'RequestURLs',
                         4: 'RegisterEx', 5: 'TestConnectivity', 6: 'UpdateURLs',
                         7: 'ReplaceURL', 8: 'SendReport'},
    'Matchmaking': {1: 'RegisterGathering', 2: 'UnregisterGathering',
                    3: 'UnregisterGatherings', 4: 'UpdateGathering', 5: 'Invite',
                    6: 'AcceptInvitation', 7: 'DeclineInvitation', 8: 'CancelInvitation',
                    9: 'GetInvitationsSent', 10: 'GetInvitationsReceived',
                    11: 'Participate', 12: 'CancelParticipation',
                    13: 'GetParticipants', 14: 'AddParticipants',
                    15: 'GetDetailedParticipants', 16: 'GetParticipantsURLs',
                    17: 'GetGathering', 18: 'GetAllGatherings', 19: 'FindGathering',
                    20: 'FindGatheringByType', 21: 'FindGatheringByParticipant',
                    22: 'UpdateHostURL', 23: 'UpdateSessionURL', 24: 'GetSessionURL',
                    25: 'GetState', 26: 'SetState'},
    'NATTraversal': {1: 'RequestProbeInitiation', 2: 'InitiateProbe',
                     3: 'RequestProbeInitiationExt', 4: 'ReportNATProperties',
                     5: 'GetNATProperties', 6: 'GetRelaySignatureKey',
                     7: 'ReportNATTraversalResult', 8: 'ReportNATTraversalResultDetail'},
    'Notification': {1: 'ProcessNotificationEvent'},
    'RMC': {1: 'Respond'},
}

def read_u8(data, offset):
    return data[offset], offset + 1

def read_u16_le(data, offset):
    return struct.unpack_from('<H', data, offset)[0], offset + 2

def read_u32_le(data, offset):
    return struct.unpack_from('<I', data, offset)[0], offset + 4

def read_string(data, offset):
    """NEX length-prefixed string: U16 len (includes null), then bytes."""
    if offset + 2 > len(data):
        return None, offset
    length, offset = read_u16_le(data, offset)
    if offset + length > len(data):
        return None, offset
    s = data[offset:offset+length].rstrip(b'\x00').decode('utf-8', errors='replace')
    return s, offset + length

def read_buffer(data, offset):
    """NEX buffer: U32 len, then bytes."""
    if offset + 4 > len(data):
        return None, offset
    length, offset = read_u32_le(data, offset)
    if offset + length > len(data):
        return None, offset
    return data[offset:offset+length], offset + length

def hexdump(data, prefix='    ', max_bytes=512):
    lines = []
    for i in range(0, min(len(data), max_bytes), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{prefix}{i:04x}: {hex_part:<48}  {asc_part}')
    if len(data) > max_bytes:
        lines.append(f'{prefix}... ({len(data) - max_bytes} more bytes)')
    return '\n'.join(lines)

def parse_qrv(data: bytes) -> dict:
    """
    QRV / RMC frame:
      REQUEST:  [U32 size][U16 proto_len][proto\0][U8 0x00][U8 0x01=type][U32 call_id][U32 method_id][payload...]
      RESPONSE: [U32 size][U16 proto_len][proto\0][U8 0x02=type][U8 success][U32 call_id][U32 method_id|0x8000][payload...]

    Note: NEX wraps RMC as [U32 total_size] then the RMC body starting with
    a protocol identifier byte OR the full proto-name string.  The exact
    layout varies by NEX version.  We try the string-based layout first
    then fall back to the byte-ID layout.
    """
    result = {'raw': data, 'parse_errors': []}
    offset = 0

    if len(data) < 4:
        result['parse_errors'].append('data too short')
        return result

    # U32 payload_size (= total size of the rest of the frame, not including this field)
    payload_size, offset = read_u32_le(data, offset)
    result['payload_size'] = payload_size

    if offset + 2 > len(data):
        result['parse_errors'].append('truncated after payload_size')
        return result

    # Check whether the next two bytes look like a string length
    # (proto_name_len in range 1..64) or like a single protocol-ID byte
    peek_u16 = struct.unpack_from('<H', data, offset)[0]

    if 1 <= peek_u16 <= 64 and offset + 2 + peek_u16 <= len(data):
        # String-based layout
        proto_name, offset = read_string(data, offset)
        result['proto_name'] = proto_name
    else:
        # Byte-ID layout: single U8 proto id
        proto_id, offset = read_u8(data, offset)
        result['proto_id'] = proto_id
        result['proto_name'] = f'Protocol#{proto_id}'
        # skip second byte (often 0x00 padding or extra flag)
        if offset < len(data):
            offset += 1

    if offset >= len(data):
        return result

    # U8 message type: 0x01=request, 0x02=response
    msg_type, offset = read_u8(data, offset)
    result['msg_type'] = msg_type
    result['msg_type_name'] = {1: 'REQUEST', 2: 'RESPONSE'}.get(msg_type, f'UNK({msg_type:#x})')

    if offset >= len(data):
        return result

    # U8 success flag (response) or extra flag (request)
    flag_byte, offset = read_u8(data, offset)
    result['flag_byte'] = flag_byte
    if msg_type == 2:
        result['success'] = (flag_byte == 1)

    if offset + 4 > len(data):
        return result

    # U32 call_id
    call_id, offset = read_u32_le(data, offset)
    result['call_id'] = call_id

    if offset + 4 > len(data):
        return result

    # U32 method_id (response has bit 0x8000 set in upper half)
    method_id_raw, offset = read_u32_le(data, offset)
    method_id = method_id_raw & 0x7FFF
    result['method_id_raw'] = method_id_raw
    result['method_id'] = method_id

    # Look up friendly method name
    proto = result.get('proto_name', '')
    for known_proto, methods in KNOWN_PROTOCOLS.items():
        if known_proto.lower() in proto.lower():
            result['method_name'] = methods.get(method_id, f'Method#{method_id}')
            break
    else:
        result['method_name'] = f'Method#{method_id}'

    result['body'] = data[offset:]
    result['body_offset'] = offset
    return result

# ── Per-protocol body parsers ─────────────────────────────────────────────────

def parse_login_with_token_v2_response(data: bytes) -> str:
    """Parse Authentication::LoginWithTokenV2 response body."""
    lines = []
    offset = 0
    try:
        # U32 return_value (result code)
        retval, offset = read_u32_le(data, offset)
        lines.append(f'  return_value: {retval:#010x}  ({("OK" if retval==0x10001 else "ERR")})')
        # U32 pid (principal ID)
        pid, offset = read_u32_le(data, offset)
        lines.append(f'  pid: {pid}')
        # Ticket buffer (U32 len + bytes)
        ticket, offset = read_buffer(data, offset)
        if ticket:
            lines.append(f'  ticket ({len(ticket)} bytes): {ticket.hex()}')
        # RVConnectionData
        #   regular_protocols: StationURL string
        url1, offset = read_string(data, offset)
        lines.append(f'  station_url_regular: {url1}')
        #   special_protocols: U8 count + list (often 0)
        if offset < len(data):
            count, offset = read_u8(data, offset)
            lines.append(f'  special_protocol_count: {count}')
        #   special_station_url
        if offset < len(data):
            url2, offset = read_string(data, offset)
            lines.append(f'  special_station_url: {url2}')
        # server_name string
        if offset < len(data):
            srv, offset = read_string(data, offset)
            lines.append(f'  server_name: {srv}')
    except Exception as e:
        lines.append(f'  [parse error: {e}]')
    return '\n'.join(lines)

def parse_secure_register_response(data: bytes) -> str:
    lines = []
    offset = 0
    try:
        retval, offset = read_u32_le(data, offset)
        lines.append(f'  return_value: {retval:#010x}')
        cid, offset = read_u32_le(data, offset)
        lines.append(f'  connection_id: {cid}')
        url, offset = read_string(data, offset)
        lines.append(f'  public_station_url: {url}')
    except Exception as e:
        lines.append(f'  [parse error: {e}]')
    return '\n'.join(lines)

def parse_nat_report_response(data: bytes) -> str:
    lines = []
    offset = 0
    try:
        # ReportNATProperties / GetNATProperties contain NAT-type enums
        if len(data) >= 1:
            nat_type, offset = read_u8(data, offset)
            nat_names = {0:'UNKNOWN',1:'OPEN',2:'MODERATE',3:'STRICT',4:'SYMMETRIC'}
            lines.append(f'  nat_type: {nat_names.get(nat_type, nat_type)}')
        if len(data) >= 2:
            nat_mapping, offset = read_u8(data, offset)
            lines.append(f'  nat_mapping: {nat_mapping}')
        if len(data) >= 3:
            nat_filtering, offset = read_u8(data, offset)
            lines.append(f'  nat_filtering: {nat_filtering}')
        if offset + 4 <= len(data):
            rtt, offset = read_u32_le(data, offset)
            lines.append(f'  rtt_ms: {rtt}')
    except Exception as e:
        lines.append(f'  [parse error: {e}]')
    return '\n'.join(lines)

def parse_body_generic(proto_name: str, method_id: int, msg_type: int, data: bytes) -> str:
    """Best-effort structured parse for known methods."""
    pn = proto_name.lower() if proto_name else ''
    if 'auth' in pn and method_id in (100, 101):
        return parse_login_with_token_v2_response(data)
    if 'secure' in pn and method_id == 1:
        return parse_secure_register_response(data)
    if 'nat' in pn:
        return parse_nat_report_response(data)
    return ''

# ── Main analysis ─────────────────────────────────────────────────────────────

PACKETS = {
    # pkt_num: (direction, hex_string)
    13:  ("server→client (LoginWithToken_V2 response)",
          "313f72a42ae107e1010000ab000dffd8"
          "e0dd3fec70ceb2fd647186615ba70c74640d013085c6b7279e15cd109a29ee5a984c58db655ceaff81b4020a3297fbef6edd97e4a75bf1aae5e813b241d329c99841eadb73b269d5d962e8f76130d557d830410906123905eeeae1f9fbd93de3a228ae593f3b99e9d35c94f6e5056d308b37d13198d59af62f0c72cb5ab1412faf6561bcf5cf7c42ba0a2b900fad90f1c2c11596ea8c148d3b264fa704abb556898d683799fc6ca9152cb23c"),
    15:  ("client→server (request after LoginWithToken_V2)",
          "3f3172a42ae107e102000066000d0de8"
          "ff509ee9735f7dcd24ba11b83b6e2f5cdf10b3f2a1cc3c8e2fe7aee25f50e84d2aa5d83fc1b2d66aa12bc1efa7f6eff04f3b31fad1fa56c3f93f9fc696fde5b14d4c5c7f6f1e5f5c25e5c6c84e99ef8b2b4c71b6cf28fb0e87a6d7f02e93c4ead9a5d32b3edea87df47acb"),
    17:  ("server→client (response to pkt 15)",
          "313f72a42ae107e10300008c000dffd8"
          "20d3bfc37de83a76a3fb4e9c80fbbab94e9a4e3bba1a43e2e51a86e6af7e461e2ef3a7b8e3e2fe8aca24fef1aa8d15c46a47e7e4c22e4f8ddc5e41faaedafd1ce4ae3e98a62f8ca6a1abf6ef4b04dab2f0fcf3d27a31f2bab3c1b"),
    19:  ("client→server",
          "3f3172a42ae107e104000041000d0d00"
          "d2be97fff9b327d1d4ee0bc476e6b8e9bcd8a7b76a86f7acfbaabb62bc84f62f0f0b66c92aa20aac2e8ba7765c7eb7ff92f2c3ec8ee9c3f8d2d2f8aed3a97f6df7c5d9afa9d2c4dc82f0b55c"),
    21:  ("server→client (large, frag 1)",
          "313f72a42ae107e10500024f000dffd8"
          "a8af93ee0c2e4e46f6a46ad40ed9fe9b14c8e3af8a94e28ea63cdebfaf843f77e48bce3f8be9e5e4fe8e9aeecfb0f5d3da93c0c7b4c8efcaeecae6cbc7b2b3ca93e3e2bababcc0b7bacee2c0a8b1d0b4b8d1baecabcae6c9b8c9c7bab7c2cbadc4cabcc3c9c8d3b6ccd5c0b5c7d0b8bfcac9bcc3d3b2c8d7bbbcc9c2b9bfcdd8b6c9d2b7bdb7cebebac7b9c4c9c8e5b5cbc8b6b8c6cdb9bccbd0b7c8d3b8b7c9c1bab0cdd9b6b8cbb7bac6cebbb0ccd7b7b7cec3b8b5cac8bbbccdcfb6bdd2b8b4c9c1b7b0cac8b4bfcbc8b4bfccc7b3becbc5b4bdc9c4b2bbccc7b4b8c9c3b0beccc6b4bdcbc0b3bdc9c5b1bfcbc6b4beccc5b4bbc9c4b3bacbc9b4beccc4b5bcc9c3b4bbcbc4b4bbc8c3b3bcccc3b4b9c8c3b4b9ccc2b5b9cbc3b5baccc0b2bacbc2b5b9ccc4b4b9c9c5b5baccc5b3b8cbc3b6baccc4b3b9cac0b3bfccc2b3bdc9c0b5becbc5b4beccc3b3bdc9c2b6beccc1b4bec9c5b5beccc1b4bdc8c5b6bfccc4b5bdc8c2b6c0ccc4b4bfc8c3b5c0cdc2b5bcc8c3b6bfcdb3b3bfccc3b4b9c9c1b3b9cac1b3b9ccc4b4b9ccc4b5b9c9c5b5baccc5b3b7cac0b3bfccc3b3bdc8c3b5beccc3b3bec9c3b4beccc2b4bcc9c2b5bfcac5b6beccc0b3bec9c3b6beccc1b3bec9c2b6bfcdc0b3bfc8c3b6c1ccc2b3bec8c4b6c0cdc4b4bec8c4b5bfcdb0b4bcca"),
    22:  ("server→client (large, frag 2)",
          "313f72a42ae107e106000088000dffd8"
          "b4becc5b4c0cac4b6bfccc4b4bec8c4b5bfcdb0b4bccab4bfccc4b4bec8c4b5bfcdb0"),
    45:  ("client→server",
          "3f3172a42ae107e108000052000d0de8"
          "97bee0b2f3e4c8b5b4bdf1d3a4c6e8e0e6edd9c5be8edcc5d5d7cbbfa8c3d5d4cbbea3d1c8d7cfbba8ced0cdd4c4b9a5cad4d0c1b5a0cfc5d3c7c2b2a5cdd3cbb3b9a5cdd5cbb7bfaacdd7c9b3b7afcdd5ccb7ba"),
    46:  ("client→server",
          "3f3172a42ae107e10900004d000d0de8"
          "89b3e5b4f1e4cbbaafbeeed9a9cbeae2e7ecd9c8b78acdc1d3d4c9c3a7c2d4d3cac1a2d1c9d5cfc4a6cdd3d0c4b0a2cec4d1c8c2b2a5cdd3cbb3b9a5cdd5cbb7bf"),
    47:  ("client→server",
          "3f3172a42ae107e10a00004d000d0de8"
          "9fb3e0b0f2e4cbbbaebeeed8a8caeae1e7ecd8c8b78bcdc0d2d5c8c3a8c2d4d2cac1a2d1c8d5cec4a6cdd2d0c4b0a2cec3d1c8c2b2a6cdd4cbb4b8a4cdd4ccb8be"),
    48:  ("client→server (larger)",
          "3f3172a42ae107e10b000092000d0de8"
          "7eb5e5b4f8eecdb7b3c3f1d8a0ceede6ecf4d8c4bb87d3c7d9d8d5d0a5cad7d7d2d1a2d7ced9d6c1a4d2d3d5d4cab9a6d5d8d7d4c5bca5d2d3d0d3c9baa7d0d7d0d7c6bba5d2d7d3d4c3b8a5d3d8cfd7c4b9a8d1d4d3d6c2baaad2d7d2d8c4b9aad3d8d4d8c3b8a9d2d3d4d9c5bca7d2d8d0d7c2b8a9d4d8d4d7c4b7a9d3d9d0d5c1b8aad5dad0d7c3b8a8d2d4d2d7c3b8aad4d9d2d7c3b6abd5d8d1d9c5b7a8d3d4d3d8c5b9a8d3d6d3"),
    53:  ("server→client (after relay contact)",
          "313f72a42ae107e11000007f000dffd8"
          "00d53fec70c1b23369b28a6f286838f2a503093083c67076c74a124b9a27bb51b561e954889dc1e2c9167cb6a7509154e5da4fc6cd5ef727f9925992410bf6bd3ec40c18d5358eac4f204d67caefcea8233651f599169da7fc0af622e35ce3926116edb4e904b0de32f3bcd90d2e2a1382383ee970c4423e3e518600e12754c7"),
    62:  ("server→client",
          "313f72a42ae107e11100007a000dffd8"
          "40de3fec70c9b2316973806b2265c8bce9c7c2fd8ec5732ac44a1a680ee22e0626b6fefe3bce6dbb6b33664fc562b23b713fabe2c7d55370572cbd7ef1b784dab47a1722e814f1cdcf2f74b3b8d58298de32eaf187828d013e88da0a8c1c7415aa8038f7b1edd44a754a2a7fcf9bdf86668ef1343e3a3b690d8947"),
    64:  ("server→client",
          "313f72a42ae107e11200003d000dffd8"
          "a8749f4c406052a8b264da3b1db57a2f39585d8ad67526fac945bb206e62788f6eb30eaf179ea186e477f1a140a5105793a2a3adc112f90d8c16c6514bee"),
    74:  ("server→client",
          "313f72a42ae107e11400005f000dffd8"
          "ec4b4c3e27c68218da35bfee00e523085ad55046d1e3bc96e24c07b571505427c28fa2e2c89ff6afb4af14dfb5a540d4d9e6e8f2b78aec42e87e6dd958e1c6c71ca6bcecfffe2a8afaef0c97d838e7"),
    76:  ("server→client",
          "313f72a42ae107e11500005f000dffd8"
          "ec4b4c3e278482aedc37bfee00df23085ad56042d3e3bc96e24c07b571505527c28fa2e2c89ff6afb4af14dfb5a540d4d9e6e8f2b78aec42e87e6dd958e1c6c71ca6bcecfffe2a8afaef0c97d838e7"),
    78:  ("server→client",
          "313f72a42ae107e11600005f000dffd8"
          "ec4b4c3e276c82c2db36bfee00dd23085ad56045d3e3bc96e24c07b571505627c28fa2e2c89ff6afb4af14dfb5a540d4d9e6e8f2b78aec42e87e6dd958e1c6c71ca6bcecfffe2a8afaef0c97d838e7"),
    81:  ("server→client",
          "313f72a42ae107e11700006c000dffd8"
          "ec4b4c3e271082f6db36bfee00db23085ad56048d3e3bc96e24c07b571505727c28fa2e2c89ff6afb4af14dfb5a540d4d9e6e8f2b78aec42e87e6dd958e1c6c71ca6bcecfffe2a8afaef0c97d838e7c6c58f21ca20c77b6c"),
}

def analyze_packet(pkt_num: int, direction: str, hex_str: str):
    sep = '=' * 72
    print(f'\n{sep}')
    print(f'PACKET {pkt_num}  ({direction})')
    print(sep)

    # Normalise hex (remove spaces/newlines)
    hex_str = hex_str.replace(' ', '').replace('\n', '')
    raw = bytes.fromhex(hex_str)
    print(f'  Raw length: {len(raw)} bytes')

    # Parse PRUDP header
    try:
        hdr = parse_prudp(raw)
    except Exception as e:
        print(f'  PRUDP parse error: {e}')
        return

    src_st = STREAM_TYPES.get(hdr['src_stream'], f"Stream{hdr['src_stream']}")
    dst_st = STREAM_TYPES.get(hdr['dst_stream'], f"Stream{hdr['dst_stream']}")
    print(f'  PRUDP:  src={src_st}:{hdr["src_port"]}  dst={dst_st}:{hdr["dst_port"]}')
    print(f'          type={hdr["pkt_type_name"]}  flags=[{",".join(hdr["flag_names"])}]')
    print(f'          session_id={hdr["session_id"]:#04x}  signature={hdr["signature"]:#010x}  seq={hdr["seq_id"]}')
    if hdr['part_number'] is not None:
        print(f'          part_number={hdr["part_number"]}')
    if hdr['payload_size_field'] is not None:
        print(f'          payload_size_field={hdr["payload_size_field"]}')
    print(f'          payload: {len(hdr["payload"])} bytes  checksum={hdr["checksum"]:#010x}')

    # Only decrypt DATA packets on RVSecure stream
    if hdr['pkt_type'] != 2:
        print(f'  (Not DATA — no payload to decrypt)')
        return
    if hdr['src_stream'] != 3 and hdr['dst_stream'] != 3:
        print(f'  (Not RVSecure stream — skipping decrypt)')
        return

    payload = hdr['payload']
    if len(payload) == 0:
        print('  (Empty payload)')
        return

    # RC4 decrypt
    dec = rc4(RC4_KEY, payload)
    print(f'  Decrypted ({len(dec)} bytes): {dec[:32].hex()}{"..." if len(dec)>32 else ""}')

    # Compression byte
    comp = dec[0]
    body = dec[1:]
    print(f'  Compression byte: {comp}  ({"uncompressed" if comp==0 else f"zlib, ratio={comp}"})')

    if comp != 0 and len(body) > 0:
        try:
            body = zlib.decompress(body)
            print(f'  Decompressed to {len(body)} bytes')
        except Exception as e:
            print(f'  zlib error: {e}  (treating as raw)')

    print(f'  QRV body ({len(body)} bytes):')
    print(hexdump(body, prefix='    ', max_bytes=320))

    # Parse QRV
    qrv = parse_qrv(body)
    print(f'  QRV parse:')
    for key in ('payload_size', 'proto_id', 'proto_name', 'msg_type_name',
                'flag_byte', 'success', 'call_id', 'method_id_raw', 'method_id', 'method_name'):
        if key in qrv:
            print(f'    {key}: {qrv[key]}')
    if qrv.get('parse_errors'):
        print(f'    parse_errors: {qrv["parse_errors"]}')

    rbd = qrv.get('body', b'')
    if rbd:
        print(f'  Body/response payload ({len(rbd)} bytes):')
        print(hexdump(rbd, prefix='    ', max_bytes=320))
        # Try structured parse
        proto = qrv.get('proto_name', '')
        mid   = qrv.get('method_id', 0)
        mt    = qrv.get('msg_type', 0)
        detail = parse_body_generic(proto, mid, mt, rbd)
        if detail:
            print(f'  Structured parse:')
            print(detail)


def main():
    print('Watch Dogs 1 — PRUDP V0 packet analysis')
    print('RC4 key: "CD&ML"  |  Stream: RVSecure (type 3)')
    for pkt_num in sorted(PACKETS.keys()):
        direction, hex_str = PACKETS[pkt_num]
        analyze_packet(pkt_num, direction, hex_str)
    print('\n' + '='*72)
    print('Done.')


if __name__ == '__main__':
    main()
