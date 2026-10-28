import importlib.util
import io
import json
import os
import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
spec = importlib.util.spec_from_file_location('audit', Path(__file__).with_name('audit-artifacts.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def zip_bytes(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(name, content)
    return output.getvalue()


def elf_bytes(payload, bits=64, endian='<', section_name=b'payload'):
    # Minimal valid section-table fixture, independent of Android build tools.
    ident = b'\x7fELF' + bytes([2 if bits == 64 else 1, 1 if endian == '<' else 2, 1]) + bytes(9)
    header_size, section_size = (64,64) if bits==64 else (52,40)
    strings = b'\0.shstrtab\0' + section_name + b'\0'
    payload_offset = header_size + len(strings)
    table_offset = payload_offset + len(payload)
    if bits==64:
        header = struct.pack(endian+'HHIQQQIHHHHHH',3,183,1,0,0,table_offset,0,header_size,0,0,section_size,3,1)
        section = lambda name, offset, size: struct.pack(endian+'IIQQQQIIQQ',name,1,0,0,offset,size,0,0,1,0)
    else:
        header = struct.pack(endian+'HHIIIIIHHHHHH',3,40,1,0,0,table_offset,0,header_size,0,0,section_size,3,1)
        section = lambda name, offset, size: struct.pack(endian+'IIIIIIIIII',name,1,0,0,offset,size,0,0,1,0)
    return ident + header + strings + payload + bytes(section_size) + section(1,header_size,len(strings)) + section(11,payload_offset,len(payload))


def dex_bytes(strings):
    header = bytearray(112)
    header[:8] = b'dex\n039\0'
    table = bytearray()
    payload = bytearray()
    for value in strings:
        table.extend(struct.pack('<I', 112 + 4 * len(strings) + len(payload)))
        payload.extend(bytes([len(value)]) + value + b'\0')
    struct.pack_into('<III', header, 32, 112 + len(table) + len(payload), 112, 0x12345678)
    struct.pack_into('<II', header, 56, len(strings), 112)
    return header + table + payload


def xalz_bytes(data):
    # A valid literal-only LZ4 block, independent of the production decoder.
    extra = len(data)-15
    block = bytes([min(len(data), 15) << 4])
    if extra >= 0:
        block += bytes([255])*(extra//255) + bytes([extra%255])
    return b'XALZ' + struct.pack('<II', 0, len(data)) + block + data


class ArtifactTests(unittest.TestCase):
    def test_native_aot_is_scanned_without_misclassifying_it_as_a_dll_wrapper(self):
        name = 'lib/arm64-v8a/libaot-App.dll.so'
        aot = elf_bytes(b'native\0mono_aot_file_info\0', section_name=b'.text')
        audit.inspect_payload(aot, name)
        with self.assertRaisesRegex(ValueError, 'forbidden'):
            audit.inspect_payload(aot + b'io/sentry/android', name)
        with self.assertRaisesRegex(ValueError, 'no inspectable payload'):
            audit.inspect_payload(elf_bytes(b'native', section_name=b'.text'), name)
        with self.assertRaisesRegex(ValueError, 'no inspectable payload'):
            audit.inspect_payload(aot, 'lib/arm64-v8a/lib_App.dll.so')

    def test_compressed_assemblies_are_decompressed_and_scanned(self):
        safe = b'MZ' + b'a'*1024
        self.assertEqual(audit.unpack_xalz(xalz_bytes(safe)), safe)
        # Literal MZa, overlapping match offset=1, then the final five literals.
        overlap = b'XALZ' + struct.pack('<II', 0, 28) + b'\x3fMZa\x01\x00\x01\x50abcde'
        self.assertEqual(audit.unpack_xalz(overlap), b'MZ'+b'a'*21+b'abcde')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'app.apk'
            for marker in (b'Microsoft.AppCenter', b'io/sentry/android', b'io/opentelemetry'):
                path.write_bytes(zip_bytes({'lib/arm64-v8a/lib_test.dll.so':elf_bytes(xalz_bytes(b'MZ'+marker))}))
                with self.subTest(marker=marker), self.assertRaisesRegex(ValueError, 'forbidden'):
                    audit.archive(path)
            path.write_bytes(zip_bytes({'lib/arm64-v8a/lib_test.dll.so':elf_bytes(xalz_bytes(safe))}))
            audit.archive(path)
            with patch.object(audit, 'MAX_APK_BYTES', len(path.read_bytes())):
                with self.assertRaisesRegex(ValueError, 'size limit'):
                    audit.archive(path, apk=True)
        for bad in (xalz_bytes(safe)[:-1], b'XALZ'+struct.pack('<II',0,2**31)+b'\0',
                    b'XALZ'+struct.pack('<II',0,5)+b'\x10M\0\0',
                    b'XALZ'+struct.pack('<II',0,5)+b'\x10M\x02\0'):
            with self.subTest(bad=bad[:16]), self.assertRaises(ValueError):
                audit.unpack_xalz(bad)

    def test_apk_requires_only_real_arm64_native_libraries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'app.apk'
            files = {'AndroidManifest.xml': b'manifest',
                     'classes.dex': dex_bytes([b'Lokhttp3/OkHttpClient;']),
                     'lib/arm64-v8a/libargon2.so': elf_bytes(b'native', section_name=b'.text')}
            path.write_bytes(zip_bytes(files))
            audit.archive(path, apk=True, expected_abi='arm64-v8a')
            wrong_machine = bytearray(files['lib/arm64-v8a/libargon2.so'])
            struct.pack_into('<H', wrong_machine, 18, 40)
            cases = [
                {**files, 'lib/x86_64/extra.so': elf_bytes(b'native')},
                {**files, 'lib/arm64-v8a/libargon2.so': bytes(wrong_machine)},
                {k: v for k, v in files.items() if not k.endswith('libargon2.so')},
            ]
            for invalid in cases:
                path.write_bytes(zip_bytes(invalid))
                with self.assertRaises(ValueError):
                    audit.archive(path, apk=True, expected_abi='arm64-v8a')

    def test_apk_budget_is_separate_and_both_limits_remain_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'app.apk'
            path.write_bytes(zip_bytes({'AndroidManifest.xml': b'manifest',
                                        'classes.dex': dex_bytes([b'Lokhttp3/OkHttpClient;'])}))
            with patch.object(audit, 'MAX_ARCHIVE_BYTES', 32), patch.object(audit, 'MAX_APK_BYTES', 1024):
                audit.archive(path, apk=True)
                with self.assertRaisesRegex(ValueError, 'inspection size limit'):
                    audit.archive(path)
            with patch.object(audit, 'MAX_APK_BYTES', 32):
                with self.assertRaisesRegex(ValueError, 'inspection size limit'):
                    audit.archive(path, apk=True)
            with patch.object(audit, 'MAX_ENTRY_BYTES', 8):
                with self.assertRaisesRegex(ValueError, 'entry size limit'):
                    audit.archive(path, apk=True)

    def test_real_kotlin_binding_is_not_sentry(self):
        fixture = os.environ.get('KOTLIN_AUDIT_FIXTURE')
        if not fixture:
            self.skipTest('Official Kotlin fixture is supplied by CI')
        import hashlib
        package = Path(fixture).read_bytes()
        self.assertEqual(hashlib.sha256(package).hexdigest(),
                         'b07e498f7714f476fb50ef81f6b21496acfdb000bc9ac058c4ba6eacad68494c')
        with zipfile.ZipFile(io.BytesIO(package)) as archive:
            dll = archive.read('lib/net8.0-android34.0/Xamarin.Kotlin.StdLib.dll')
        self.assertIn(b'sEntry.', dll.replace(b'\0', b''))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'app.apk'
            path.write_bytes(zip_bytes({'AndroidManifest.xml': b'manifest',
                                        'classes.dex': dex_bytes([b'Lokhttp3/OkHttpClient;']),
                                        'lib/arm64-v8a/lib_kotlin.dll.so': elf_bytes(dll)}))
            audit.archive(path, apk=True)

    def test_real_androidx_binding_constants_and_wrapper(self):
        fixture = os.environ.get('ANDROIDX_AUDIT_FIXTURE')
        if not fixture:
            self.skipTest('Official AndroidX fixture is supplied by CI')
        import hashlib
        package = Path(fixture).read_bytes()
        self.assertEqual(hashlib.sha256(package).hexdigest(), '2c4e2d327789ecb58e95feb73aa712b75c300c2674d6b51a55f28f7d3a54157a')
        with zipfile.ZipFile(io.BytesIO(package)) as archive:
            dll = archive.read('lib/net8.0-android34.0/Xamarin.AndroidX.Activity.dll')
        self.assertIn(b'com.google.android.gms.provider.action.PICK_IMAGES'.decode().encode('utf-16-le'), dll)
        audit.inspect_payload(dll, 'Xamarin.AndroidX.Activity.dll')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'app.apk'
            def write(payload):
                path.write_bytes(zip_bytes({'AndroidManifest.xml': b'manifest',
                                            'classes.dex': dex_bytes([b'Lokhttp3/OkHttpClient;']),
                                            'lib/arm64-v8a/lib_binding.dll.so': elf_bytes(payload)}))
            write(dll)
            audit.archive(path, apk=True)
            marker = b'com.google.android.gms.provider.action.PICK_IMAGES'.decode().encode('utf-16-le')
            cases = {'telemetry': dll + b'Microsoft.AppCenter',
                     'sdk': dll + b'com.google.android.gms.Clearcut',
                     'missing_heap': dll.replace(b'#Blob\0', b'#Gone\0'),
                     'truncated_metadata': dll[:dll.index(marker)+len(marker)]}
            for label, bad in cases.items():
                with self.subTest(label=label), self.assertRaises(ValueError):
                    write(bad)
                    audit.archive(path, apk=True)
            # Marker outside the managed payload must also remain blocked.
            write(dll)
            path.write_bytes(zip_bytes({'lib/arm64-v8a/lib_binding.dll.so':
                                         elf_bytes(dll) + b'Microsoft.AppCenter'}))
            with self.assertRaisesRegex(ValueError, 'forbidden'):
                audit.archive(path)

    def test_full_apk_scan_preserves_dex_validation(self):
        literals = [b'com.google.android.gms.org.conscrypt',
                    b'com.google.android.gms.provider.action.PICK_IMAGES',
                    b'com.google.android.gms.provider.extra.PICK_IMAGES_MAX']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'app.apk'
            def write(strings):
                path.write_bytes(zip_bytes({'AndroidManifest.xml': b'manifest',
                                            'classes.dex': dex_bytes(strings)}))
            write(literals)
            audit.archive(path, apk=True)
            for marker in (b'Lcom/google/android/gms/clearcut/ClearcutLogger;',
                           b'Lcom/google/firebase/analytics/FirebaseAnalytics;',
                           b'Microsoft.AppCenter.Analytics'):
                with self.subTest(marker=marker):
                    write(literals + [marker])
                    with self.assertRaisesRegex(ValueError, 'forbidden'):
                        audit.archive(path, apk=True)

    def test_dex_tls_provider_literal_is_not_an_sdk(self):
        provider = b'com.google.android.gms.org.conscrypt'
        audit.inspect_payload(dex_bytes([provider, b'Lokhttp3/OkHttpClient;']), 'classes.dex')
        picker = [b'com.google.android.gms.provider.action.PICK_IMAGES',
                  b'com.google.android.gms.provider.extra.PICK_IMAGES_MAX']
        audit.inspect_payload(dex_bytes(picker), 'classes.dex')
        for literal in picker:
            with self.assertRaisesRegex(ValueError, 'forbidden'):
                audit.inspect_payload(dex_bytes([literal + b'.other']), 'classes.dex')
        for marker in (b'Lcom/google/android/gms/org/conscrypt/Socket;',
                       b'Lcom/google/android/gms/clearcut/ClearcutLogger;',
                       provider + b'.Socket', b'Lcom/google/firebase/analytics/FirebaseAnalytics;'):
            with self.subTest(marker=marker):
                with self.assertRaisesRegex(ValueError, 'forbidden'):
                    audit.inspect_payload(dex_bytes([provider, marker]), 'classes.dex')
        # A matching raw blob or malformed table cannot receive the exemption.
        with self.assertRaisesRegex(ValueError, 'forbidden'):
            audit.check(provider, 'vendor.jar')
        with self.assertRaisesRegex(ValueError, 'malformed DEX'):
            audit.inspect_payload(b'dex\n039\0' + provider, 'classes.dex')
        unlisted = dex_bytes([b'Lokhttp3/OkHttpClient;']) + bytes([len(provider)]) + provider + b'\0'
        struct.pack_into('<I', unlisted, 32, len(unlisted))
        with self.assertRaisesRegex(ValueError, 'forbidden'):
            audit.inspect_payload(unlisted, 'classes.dex')

    def test_nested_opencensus_canary(self):
        with tempfile.TemporaryDirectory() as d:
            aar = Path(d) / 'library.aar'
            aar.write_bytes(zip_bytes({'classes.jar': zip_bytes({'io/opencensus/stats/Stats.class': b'canary'})}))
            with self.assertRaisesRegex(ValueError, 'forbidden'):
                audit.archive(aar)

    def test_dex_and_utf16_sdk_canaries(self):
        for marker in ['Lcom/google/android/gms/clearcut/ClearcutLogger;', 'Microsoft.Identity.Client',
                       'com.samsung.android.providers.context.permission.WRITE_USE_APP_FEATURE_SURVEY']:
            for encoding in ['utf-8', 'utf-16-le']:
                with self.subTest(marker=marker, encoding=encoding):
                    with self.assertRaises(ValueError):
                        audit.check(marker.encode(encoding), 'canary')

    def test_custom_network_libraries_allowed(self):
        audit.check(b'okhttp3/OkHttpClient com/jcraft/jsch/Session FluentFTP SMBLibrary '
                    b'https://vault.internal/webdav com/google/android/material com/google/common/collect', 'transport')
        audit.check('sEntry.'.encode('utf-16-le'), 'Kotlin identifier')
        for marker in ('Sentry.SentrySdk', 'Sentry/Protocol/Event', 'io.sentry.android.core',
                       'io/sentry/android/core/SentryAndroid'):
            with self.subTest(marker=marker), self.assertRaisesRegex(ValueError, 'forbidden'):
                audit.check(marker.encode('utf-16-le'), 'telemetry SDK')

    def test_resource_marker_is_rejected_with_specific_diagnostic(self):
        for encoding in ('utf-8', 'utf-16-le'):
            with self.subTest(encoding=encoding):
                with self.assertRaisesRegex(ValueError, "'MegaApiClient' found in resources.arsc"):
                    audit.check('Upgraded MegaApiClient and okhttp'.encode(encoding), 'resources.arsc')

    def test_restored_graph_and_empty_graph(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with self.assertRaises(ValueError):
                audit.assets(root)
            path = root / 'project.assets.json'
            for libs, good in [({},True), ({'FluentFTP/52.1.0':{},'SMBLibrary/1.5.4':{}},True),
                               ({'Xamarin.GooglePlayServices.Auth/121.3.0.1':{}},False)]:
                path.write_text(json.dumps({'version': 3, 'libraries': libs,
                                            'targets': {'net9.0-android35.0': libs},
                                            'project': {'frameworks': {'net9.0-android35.0': {}}}}))
                if good:
                    self.assertEqual(audit.assets(root), 1)
                else:
                    with self.assertRaises(ValueError):
                        audit.assets(root)

    def test_incomplete_restored_graphs_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = root / 'project.assets.json'
            base = {'version': 3, 'libraries': {}, 'targets': {'net9.0-android35.0': {}},
                    'project': {'frameworks': {'net9.0-android35.0': {}}}}
            invalid = [{}, {'libraries': {}}, {**base, 'libraries': None},
                       {**base, 'targets': {}}, {**base, 'targets': {'net9.0-android35.0': None}},
                       {**base, 'targets': {'net9.0-android35.0': {'FluentFTP/52.1.0': {}}}},
                       {**base, 'project': {}},
                       {**base, 'projectFileDependencyGroups': {'net9.0-android35.0': ['FluentFTP >= 52.1.0']}},
                       {**base, 'project': {'frameworks': {'net9.0-android35.0': {
                           'dependencies': {'FluentFTP': {'version': '[52.1.0, )'}}}}}}]
            for doc in invalid:
                with self.subTest(doc=doc):
                    path.write_text(json.dumps(doc))
                    with self.assertRaises(ValueError):
                        audit.assets(root)

    def test_compressed_assemblies_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'app.apk'
            for name, content in [('assemblies.blob', b'opaque'), ('a.dll', b'XALZcompressed')]:
                path.write_bytes(zip_bytes({name:content}))
                with self.assertRaisesRegex(ValueError, 'compressed assemblies|assembly store'):
                    audit.archive(path)

    def test_elf_wrapped_compressed_assemblies_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'app.apk'
            for bits in (32,64):
                for endian in ('<','>'):
                    for magic in (b'XALZ',b'XABA'):
                        with self.subTest(bits=bits,endian=endian,magic=magic):
                            path.write_bytes(zip_bytes({'lib/arm64-v8a/opaque.so':elf_bytes(magic+b'opaque',bits,endian)}))
                            with self.assertRaisesRegex(ValueError,'compressed assemblies|assembly store'):
                                audit.archive(path)

    def test_plain_elf_payload_is_scanned_and_native_library_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'library.aar'
            path.write_bytes(zip_bytes({'lib/arm64-v8a/native.so':elf_bytes(b'native',section_name=b'.text')}))
            audit.archive(path)
            path.write_bytes(zip_bytes({'lib/arm64-v8a/lib_app.dll.so':elf_bytes(b'MZsafe assembly')}))
            audit.archive(path)
            path.write_bytes(zip_bytes({'lib/arm64-v8a/lib_app.dll.so':elf_bytes(b'MZMicrosoft.AppCenter')}))
            with self.assertRaisesRegex(ValueError,'forbidden'):
                audit.archive(path)

    def test_opaque_wrapper_and_new_store_name_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'library.aar'
            for name in ('libassembly-store.so','libassemblies.arm64_v8a.blob.so','lib_app.dll.so'):
                path.write_bytes(zip_bytes({name:elf_bytes(b'opaque',section_name=b'.text')}))
                with self.assertRaises(ValueError):
                    audit.archive(path)

    def test_malformed_elf_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'library.aar'
            for data in (b'\x7fELF', elf_bytes(b'XALZopaque')[:-30]):
                path.write_bytes(zip_bytes({'lib_app.dll.so':data}))
                with self.assertRaises(ValueError):
                    audit.archive(path)


if __name__ == '__main__':
    unittest.main()
