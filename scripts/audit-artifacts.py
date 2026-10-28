#!/usr/bin/env python3
"""Reject known telemetry/vendor SDKs in resolved assets and inspectable APK/AAR/JAR files.

This is a packaging regression gate, not a proof about every possible runtime request.
"""
import argparse
import io
import json
from pathlib import Path
import re
import struct
import zipfile

SDK = re.compile(rb'(?:io[/\.]opencensus|io[/\.]opentelemetry|com[/\.]google[/\.]android[/\.]gms|'
                 rb'com[/\.]google[/\.]mlkit|com[/\.]google[/\.]firebase|com[/\.]microsoft[/\.]appcenter|'
                 rb'com[/\.]dropbox|com[/\.]pcloud|com[/\.]microsoft[/\.]identity|'
                 rb'Microsoft\.(?:Identity|Graph|ApplicationInsights|AppCenter)|Xamarin\.GooglePlayServices|'
                 rb'MegaApiClient|OpenTelemetry[/\.]|io[/\.]sentry|(?-i:Sentry[/\.])|WRITE_USE_APP_FEATURE_SURVEY)', re.I)
SYSTEM_LITERALS = (b'com.google.android.gms.org.conscrypt',
                   b'com.google.android.gms.provider.action.PICK_IMAGES',
                   b'com.google.android.gms.provider.extra.PICK_IMAGES_MAX')
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_APK_BYTES = 2 * 1024 * 1024 * 1024
MAX_ENTRY_BYTES = 128 * 1024 * 1024


def check(data, label):
    # DEX/JAR names and .NET strings; Android binary XML also contains UTF-16 strings.
    match = SDK.search(data) or SDK.search(data.replace(b'\x00', b''))
    if match:
        marker = match.group().decode('ascii')
        strings = re.findall(rb'[\x20-\x7e]{4,}', data)
        contexts = [s[:240].decode('ascii') for s in strings if SDK.search(s)][:20]
        raise ValueError(f'forbidden telemetry/vendor SDK {marker!r} found in {label}; strings={contexts!r}')


def elf_payload(data):
    """Read the .NET Android payload section, without assuming its file offset."""
    if len(data) < 16 or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError('malformed ELF identification')
    endian = '<' if data[5] == 1 else '>'
    header_format = endian + ('HHIIIIIHHHHHH' if data[4] == 1 else 'HHIQQQIHHHHHH')
    section_format = endian + ('IIIIIIIIII' if data[4] == 1 else 'IIQQQQIIQQ')
    def unpack(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise ValueError('malformed ELF table bounds')
        return struct.unpack_from(fmt, data, offset)
    header = unpack(header_format, 16)
    offset, size, count, names_index = header[5], header[10], header[11], header[12]
    if not offset and not count:
        return None  # A native library may have no section table.
    if not count or size < struct.calcsize(section_format) or names_index >= count:
        raise ValueError('unsupported or malformed ELF section table')
    if offset + size * count > len(data):
        raise ValueError('malformed ELF section table bounds')
    def section(index):
        return unpack(section_format, offset + size * index)
    def content(info):
        start, length = info[4], info[5]
        if start + length > len(data):
            raise ValueError('malformed ELF section bounds')
        return data[start:start + length]
    names = content(section(names_index))
    payloads = []
    for index in range(count):
        info = section(index)
        name_offset = info[0]
        end = names.find(b'\0', name_offset)
        if name_offset >= len(names) or end < 0:
            raise ValueError('malformed ELF section name')
        if names[name_offset:end] == b'payload':
            payloads.append(content(info))
    if len(payloads) > 1:
        raise ValueError('ambiguous ELF payload sections')
    return payloads[0] if payloads else None


def check_dex(data, name):
    # OkHttp 4.12's AndroidSocketAdapter recognizes this installed TLS provider.
    # Exempt only its exact DEX string-table item, never SDK type descriptors.
    literals = SYSTEM_LITERALS
    if (len(data) < 112 or data[:4] != b'dex\n' or data[7] != 0
            or struct.unpack_from('<III', data, 32) != (len(data), 112, 0x12345678)):
        raise ValueError('malformed DEX header: ' + name)
    count, offset = struct.unpack_from('<II', data, 56)
    if offset < 112 or offset + count * 4 > len(data):
        raise ValueError('malformed DEX string table: ' + name)
    filtered = bytearray(data)
    for index in range(count):
        start, = struct.unpack_from('<I', data, offset + index * 4)
        for literal in literals:
            end = start + 1 + len(literal)
            # Exact ASCII DEX string, including ULEB128 length and terminator.
            if (start >= offset + count * 4 and end < len(data)
                    and data[start:end + 1] == bytes([len(literal)]) + literal + b'\0'):
                filtered[start:end + 1] = b'\0' * (end + 1 - start)
    result = bytes(filtered)
    check(result, name)
    return result


def check_managed(data, name):
    """Recognize only exact UTF-16 constants in the CLR #Blob metadata heap."""
    def unpack(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise ValueError('malformed PE bounds: ' + name)
        return struct.unpack_from(fmt, data, offset)
    pe, = unpack('<I', 60)
    if data[pe:pe+4] != b'PE\0\0':
        raise ValueError('malformed PE signature: ' + name)
    count, = unpack('<H', pe+6)
    optional_size, = unpack('<H', pe+20)
    optional = pe+24
    magic, = unpack('<H', optional)
    if magic not in (0x10b, 0x20b):
        raise ValueError('unsupported PE optional header: ' + name)
    directories = optional + (96 if magic == 0x10b else 112)
    if directories + 15*8 > optional + optional_size:
        raise ValueError('missing CLR directory: ' + name)
    def rva(address, length):
        for index in range(count):
            section = optional + optional_size + 40*index
            _, base, size, raw = unpack('<IIII', section+8)
            if base <= address and address + length <= base + size:
                offset = raw + address-base
                if offset + length <= len(data):
                    return offset
        raise ValueError('unmapped PE address: ' + name)
    cli_rva, _ = unpack('<II', directories+14*8)
    cli = rva(cli_rva, 16)
    metadata_rva, metadata_size = unpack('<II', cli+8)
    metadata = rva(metadata_rva, metadata_size)
    limit = metadata+metadata_size
    if data[metadata:metadata+4] != b'BSJB':
        raise ValueError('missing CLR metadata: ' + name)
    version_size, = unpack('<I', metadata+12)
    cursor = metadata+16+((version_size+3) & ~3)
    _, streams = unpack('<HH', cursor)
    cursor += 4
    blob = None
    for _ in range(streams):
        offset, size = unpack('<II', cursor)
        end = data.find(b'\0', cursor+8, min(cursor+40, limit))
        if end < 0 or metadata+offset+size > limit:
            raise ValueError('malformed CLR stream: ' + name)
        if data[cursor+8:end] == b'#Blob':
            if blob is not None:
                raise ValueError('duplicate CLR blob heap: ' + name)
            blob = (metadata+offset, metadata+offset+size)
        cursor = (end+4) & ~3
    if blob is None:
        raise ValueError('missing CLR blob heap: ' + name)
    filtered = bytearray(data)
    cursor, end = blob
    encoded_literals = {s.decode().encode('utf-16-le') for s in SYSTEM_LITERALS}
    while cursor < end:
        first = data[cursor]
        if first < 0x80:
            length, width = first, 1
        elif first < 0xc0 and cursor+2 <= end:
            length, width = ((first & 0x3f) << 8) | data[cursor+1], 2
        elif first < 0xe0 and cursor+4 <= end:
            length = ((first & 0x1f) << 24) | int.from_bytes(data[cursor+1:cursor+4], 'big')
            width = 4
        else:
            raise ValueError('malformed CLR blob length: ' + name)
        start = cursor+width
        cursor = start+length
        if cursor > end:
            raise ValueError('truncated CLR blob: ' + name)
        if data[start:cursor] in encoded_literals:
            filtered[start:cursor] = b'\0' * length
    result = bytes(filtered)
    check(result, name)
    return result


def unpack_xalz(data):
    """Decode the bounded raw LZ4 block following the .NET Android XALZ header."""
    def fail():
        raise ValueError('malformed compressed assemblies (XALZ/LZ4)')
    if len(data) < 13 or not data.startswith(b'XALZ'):
        fail()
    _, expected = struct.unpack_from('<II', data, 4)
    if not 0 < expected <= MAX_ENTRY_BYTES:
        fail()
    output = bytearray()
    cursor = 12
    def length(base):
        nonlocal cursor
        if base == 15:
            while True:
                if cursor >= len(data):
                    fail()
                value = data[cursor]
                cursor += 1
                base += value
                if base > expected:
                    fail()
                if value != 255:
                    break
        return base
    while cursor < len(data):
        token = data[cursor]
        cursor += 1
        literals = length(token >> 4)
        if cursor+literals > len(data) or len(output)+literals > expected:
            fail()
        output.extend(data[cursor:cursor+literals])
        cursor += literals
        if cursor == len(data):
            break
        if cursor+2 > len(data):
            fail()
        offset = int.from_bytes(data[cursor:cursor+2], 'little')
        cursor += 2
        if offset == 0 or offset > len(output):
            fail()
        count = length(token & 15)+4
        if len(output)+count > expected:
            fail()
        pattern = output[-offset:]
        output.extend((pattern*((count+offset-1)//offset))[:count])
    if len(output) != expected or not output.startswith(b'MZ'):
        fail()
    return bytes(output)


def inspect_payload(data, name, expansion=None):
    store = re.search(r'assembly-store|assemblies.*\.blob', name, re.I)
    if store or data.startswith(b'XABA'):
        raise ValueError('assembly store requires an unpacked validation build')
    payload = data
    wrapper = name.lower().endswith('.dll.so')
    if data.startswith(b'\x7fELF'):
        payload = elf_payload(data)
        if payload is None:
            aot = (Path(name).name.startswith('libaot-')
                   and b'mono_aot_file_info\0' in data)
            if wrapper and not aot:
                raise ValueError('managed ELF wrapper has no inspectable payload: ' + name)
            check(data, name)
            return
    embedded = payload
    if payload.startswith(b'XALZ'):
        payload = unpack_xalz(payload)
        if expansion:
            expansion(len(payload))
    if payload.startswith(b'XABA'):
        raise ValueError('assembly store requires an unpacked validation build')
    if wrapper and not payload.startswith(b'MZ'):
        raise ValueError('unknown managed ELF payload format')
    if name.lower().endswith('.dex'):
        normalized = check_dex(payload, name)
    elif payload.startswith(b'MZ') and any(s.decode().encode('utf-16-le') in payload for s in SYSTEM_LITERALS):
        normalized = check_managed(payload, name)
    else:
        check(payload, name)
        normalized = payload
    if embedded is not data:
        # Preserve inspection of ELF metadata and other sections outside the DLL.
        start = data.find(embedded)
        check(data[:start], name)
        check(data[start+len(embedded):], name)


def check_apk_abi(z, expected):
    if expected != 'arm64-v8a':
        raise ValueError('unsupported expected APK ABI')
    libraries = [n for n in z.namelist() if n.startswith('lib/') and not n.endswith('/')]
    abis = {n.split('/')[1] for n in libraries}
    if abis != {expected}:
        raise ValueError(f'APK ABI mismatch: expected {expected}, found {sorted(abis)}')
    if f'lib/{expected}/libargon2.so' not in libraries:
        raise ValueError('APK is missing the ARM64 Argon2 library')
    for name in libraries:
        if not name.endswith('.so'):
            continue
        with z.open(name) as stream:
            header = stream.read(20)
        if (len(header) != 20 or header[:6] != b'\x7fELF\x02\x01'
                or struct.unpack_from('<H', header, 18)[0] != 183):
            raise ValueError('APK contains a non-AArch64 ELF library: ' + name)


def archive(path, *, apk=False, expected_abi=None):
    budget = [0]
    size_limit = MAX_APK_BYTES if apk else MAX_ARCHIVE_BYTES
    def expansion(size):
        budget[0] += size
        if budget[0] > size_limit:
            raise ValueError('expanded assembly inspection size limit exceeded')
    def walk(blob, label, depth=0):
        if depth > 4:
            raise ValueError('archive nesting limit exceeded')
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            if apk and depth == 0 and expected_abi:
                check_apk_abi(z, expected_abi)
            if apk and depth == 0:
                print(f'APK unpacked bytes: {sum(e.file_size for e in z.infolist())}; limit: {size_limit}')
            for entry in z.infolist():
                if entry.is_dir():
                    continue
                budget[0] += entry.file_size
                if entry.file_size > MAX_ENTRY_BYTES:
                    raise ValueError(f'archive entry size limit exceeded: {entry.filename}')
                if budget[0] > size_limit:
                    raise ValueError(f'archive inspection size limit exceeded: {budget[0]} > {size_limit}')
                check(entry.filename.encode(), label)
                data = z.read(entry)
                # Fail closed for compressed assemblies rather than claim to scan their contents.
                inspect_payload(data, entry.filename, expansion)
                if entry.filename.lower().endswith(('.jar', '.aar', '.zip')):
                    walk(data, label + ':' + entry.filename, depth + 1)
            if apk and depth == 0:
                names = z.namelist()
                if 'AndroidManifest.xml' not in names or not any(re.fullmatch(r'classes\d*\.dex', n) for n in names):
                    raise ValueError('not an inspectable APK')
    walk(path.read_bytes(), str(path))


def assets(root):
    paths = list(root.rglob('project.assets.json'))
    if not paths:
        raise ValueError('no restored NuGet assets found')
    for path in paths:
        doc = json.loads(path.read_text())
        libraries, targets = doc.get('libraries'), doc.get('targets')
        if (doc.get('version') != 3 or not isinstance(libraries, dict)
                or not isinstance(targets, dict) or not targets
                or any(not isinstance(target, dict) for target in targets.values())):
            raise ValueError(f'invalid restored dependency graph: {path}')
        # Local AAR/JAR binding projects legitimately restore with zero NuGet libraries.
        # An empty library table is only consistent if no target or direct dependency needs it.
        if not libraries:
            frameworks = doc.get('project', {}).get('frameworks', {})
            groups = doc.get('projectFileDependencyGroups', {})
            if (not frameworks or any(targets.values()) or any(groups.values())
                    or any(f.get('dependencies') for f in frameworks.values())):
                raise ValueError(f'incomplete restored dependency graph: {path}')
        for target in targets.values():
            if not target.keys() <= libraries.keys():
                raise ValueError(f'incomplete restored dependency graph: {path}')
        for dependency in libraries:
            check(dependency.encode(), str(path))
    return len(paths)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--assets', type=Path)
    mode.add_argument('--archive', type=Path)
    mode.add_argument('--apk-dir', type=Path)
    parser.add_argument('--expected-abi', choices=['arm64-v8a'])
    args = parser.parse_args()
    if args.expected_abi and not args.apk_dir:
        parser.error('--expected-abi requires --apk-dir')
    if args.assets:
        print(f'Validated {assets(args.assets)} NuGet dependency graphs')
    elif args.archive:
        archive(args.archive)
        print('Archive SDK scan passed')
    else:
        paths = list(args.apk_dir.rglob('*.apk'))
        if not paths:
            raise ValueError('no APK produced')
        for path in paths:
            archive(path, apk=True, expected_abi=args.expected_abi)
        print(f'Validated {len(paths)} APK archives')


if __name__ == '__main__':
    main()
