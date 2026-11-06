#!/usr/bin/env python3
"""Patch a Wii IOS so its USB Ethernet driver works with an AX88772B/C adapter.

The Wii's driver only opens the original AX88772 (USB id 0b95:7720) and writes
an RX Control value whose bit 9 means something else on the B and C chips,
which misaligns every received packet. This tool makes the few byte changes
that fix both, and packs the result as a WAD a WAD manager can install.

    python3 wii_eth.py [--key FILE] <IOS: update-server folder or .wad> <output folder>

It writes two files: the untouched stock WAD (for rollback) and the patched
one. It refuses any IOS it has no profile for, and any copy of that IOS that
is not Nintendo's stock one.

It needs the Wii common key, which is not included: --key names either a
16-byte common-key.bin or BootMii's keys.bin from your own console. Without
--key it looks for common-key.bin, then keys.bin, in the current folder.
See README.md.
"""
import dataclasses
import hashlib
import pathlib
import struct
import subprocess
import sys

# The Wii common key is not in this file; its SHA-1 lets the tool tell the
# right key from a wrong one before it decrypts anything.
COMMON_KEY_SHA1 = 'ebeae6d2762d4d3ea160a6d8327fac9a25f8062b'
KEYS_BIN_SIZE = 0x400     # BootMii's keys.bin: a 0x100-byte header, then the OTP
KEYS_BIN_COMMON_KEY = 0x114
DEFAULT_KEY_FILES = ('common-key.bin', 'keys.bin')
TICKET_SIZE = 0x2A4
RECORDS = 0x1E4  # offset of the first content record in a TMD
RECORD = 36


@dataclasses.dataclass(frozen=True)
class Profile:
    """Where one IOS version's Ethernet driver lives and what to change in it."""
    title_id: int
    version: int
    content_id: int
    stock_tmd_sha1: str  # the stock TMD names every content's checksum
    edits: tuple  # (offset, old bytes as hex, new bytes as hex)


# The older ARM driver, as shipped in IOS80 v6944 (30,584 bytes, SHA-1
# aa6b000147dd12c838e40e58b25d3f5f510585f8). 21 bytes change.
ARM_DRIVER_EDITS = (
    (0x6DDE, '37373230', '37373262'),  # "/dev/usb/ehc/0b95/7720" -> "...772b"
    (0x6E5A, '37373230', '37373262'),  # "/dev/usb/oh0/0b95/7720" -> "...772b"
    (0x23F4, 'e2833020', 'e283302b'),  # id handed to the USB stack: 0x7700 + 0x2b
    # device-list scanner: mov/add/add building 0x0b957720 becomes
    # ldr ip, [pc]; b +0; .word 0x0b95772b (0x772b does not fit ARM immediates)
    (0x1FE4, 'e3a0c6b9e28cca57e28cce72', 'e59fc000ea0000000b95772b'),
    (0x1108, 'e3a01018', 'e3a01f46'),  # RX Control 0x018 -> 0x118 (2048-byte buffers)
    (0x1354, 'e3a01f86', 'e3a01f46'),  # RX Control 0x218 -> 0x118 (8192)
    (0x118C, 'e3a01fc6', 'e3a01f46'),  # RX Control 0x318 -> 0x118 (16384)
    (0x1330, 'e3a01044', 'e3a010c4'),  # reset on start: keep the oscillator running
    (0x15D8, 'e3a0104c', 'e3a010cc'),  # reset on shutdown: same
)

PROFILES = {
    # IOS58 v6176: what the Homebrew Channel and most homebrew run on.
    (0x000000010000003A, 6176): Profile(
        title_id=0x000000010000003A, version=6176, content_id=0x16,
        stock_tmd_sha1='3405b5e9cef169f512451f03dda41b6ab77fa632',
        edits=(
            (0x1BC0, '0b957720', '0b95772b'),  # USB product id the driver asks for
            (0x18DC, '21c60089', '21460089'),  # RX Control 0x318 -> 0x118
            (0x18F8, '21860089', '21460089'),  # RX Control 0x218 -> 0x118
            (0x1A3E, '214c', '21cc'),          # reset: keep the oscillator running
        )),
    # IOS80 v6944: the System Menu's IOS on 4.3, so Wii Settings and its
    # connection test run on this driver.
    (0x0000000100000050, 6944): Profile(
        title_id=0x0000000100000050, version=6944, content_id=0x0A,
        stock_tmd_sha1='eac33c6b821d111c4adb9b224db436d0f91ac16f',
        edits=ARM_DRIVER_EDITS),
    # ModMii's "IOS80v65535(ModMii-IOS60-v6174).wad": a patched IOS60 that
    # ModMii installs in slot 80 in place of IOS80. Same driver binary. Its
    # version, 65535, installs over whatever is in the slot.
    (0x0000000100000050, 65535): Profile(
        title_id=0x0000000100000050, version=65535, content_id=0x0A,
        stock_tmd_sha1='6c0c05c8eb884d85efbe4b653dac002ddc9fc6db',
        edits=ARM_DRIVER_EDITS),
}


@dataclasses.dataclass(frozen=True)
class Title:
    certs: bytes     # certificate chain: CA, CP, XS
    ticket: bytes
    tmd: bytes
    contents: list   # decrypted, in TMD order
    title_key: bytes  # the ticket's key, decrypted; WAD packing re-encrypts with it

    @property
    def title_id(self):
        return int.from_bytes(self.tmd[0x18C:0x194], 'big')

    @property
    def version(self):
        return struct.unpack('>H', self.tmd[0x1DC:0x1DE])[0]

    @property
    def name(self):
        return 'IOS%d-64-v%d' % (self.title_id & 0xFFFFFFFF, self.version)


def _aes(mode, key, iv, data):
    data += b'\0' * (-len(data) % 16)
    return subprocess.run(
        ['openssl', 'enc', mode, '-aes-128-cbc', '-nopad', '-K', key.hex(), '-iv', iv.hex()],
        input=data, capture_output=True, check=True).stdout


def _up(n, to):
    return (n + to - 1) // to * to


def _records(tmd):
    """(content id, index, type, size, sha1) for each content."""
    count = struct.unpack('>H', tmd[0x1DE:0x1E0])[0]
    out = []
    for k in range(count):
        o = RECORDS + RECORD * k
        out.append(struct.unpack('>IHHQ', tmd[o:o + 16]) + (tmd[o + 16:o + 36],))
    return out


def _tmd_size(blob):
    return RECORDS + RECORD * struct.unpack('>H', blob[0x1DE:0x1E0])[0]


def read_common_key(path, expect_sha1=None):
    """The Wii common key from a 16-byte key file or a BootMii keys.bin."""
    blob = pathlib.Path(path).read_bytes()
    if len(blob) == 16:
        key = blob
    elif len(blob) == KEYS_BIN_SIZE:
        key = blob[KEYS_BIN_COMMON_KEY:KEYS_BIN_COMMON_KEY + 16]
    else:
        raise ValueError('%s is neither a 16-byte key file nor a BootMii keys.bin' % path)
    if hashlib.sha1(key).hexdigest() != (expect_sha1 or COMMON_KEY_SHA1):
        raise ValueError('%s does not hold the Wii common key' % path)
    return key


def _title_key(ticket, common_key):
    iv = ticket[0x1DC:0x1E4] + b'\0' * 8
    return _aes('-d', common_key, iv, ticket[0x1BF:0x1CF])


def _content_iv(index):
    return struct.pack('>H', index) + b'\0' * 14


def _certs(blob):
    """Split concatenated certificates, keyed by the first two letters of their name."""
    out = {}
    while blob:
        rsa4096 = struct.unpack('>I', blob[:4])[0] == 0x10000
        size, name = (0x400, 0x284) if rsa4096 else (0x300, 0x184)
        out[blob[name:name + 2].decode()] = blob[:size]
        blob = blob[size:]
    return out


def _decrypt(certs, ticket, tmd, encrypted, common_key):
    key = _title_key(ticket, common_key)
    contents = []
    for (cid, index, _type, size, sha1), enc in zip(_records(tmd), encrypted):
        plain = _aes('-d', key, _content_iv(index), enc)[:size]
        if hashlib.sha1(plain).digest() != sha1:
            raise ValueError('content %08x does not match its checksum in the TMD' % cid)
        contents.append(plain)
    return Title(certs, ticket, tmd, contents, key)


def _load_dir(d, common_key):
    tmd_file, cetk = (d / 'tmd').read_bytes(), (d / 'cetk').read_bytes()
    tmd, ticket = tmd_file[:_tmd_size(tmd_file)], cetk[:TICKET_SIZE]
    c = {**_certs(tmd_file[len(tmd):]), **_certs(cetk[TICKET_SIZE:])}
    if not {'CA', 'CP', 'XS'} <= c.keys():
        raise ValueError('tmd and cetk in %s do not carry their certificates' % d)
    encrypted = [(d / ('%08x' % r[0])).read_bytes() for r in _records(tmd)]
    return _decrypt(c['CA'] + c['CP'] + c['XS'], ticket, tmd, encrypted, common_key)


def _load_wad(f, common_key):
    wad = f.read_bytes()
    header, kind, cert_size, _, ticket_size, tmd_size = struct.unpack('>I2sxxIIII', wad[:24])
    if kind != b'Is':
        raise ValueError('%s is not an installable WAD' % f)
    o = _up(header, 64)
    certs = wad[o:o + cert_size]
    o += _up(cert_size, 64)
    ticket = wad[o:o + ticket_size]
    o += _up(ticket_size, 64)
    tmd = wad[o:o + tmd_size]
    o += _up(tmd_size, 64)
    encrypted = []
    for r in _records(tmd):
        encrypted.append(wad[o:o + _up(r[3], 16)])
        o += _up(r[3], 64)
    return _decrypt(certs, ticket, tmd, encrypted, common_key)


def load(path, common_key):
    """Read an IOS from an update-server folder (tmd, cetk, contents) or a .wad."""
    path = pathlib.Path(path)
    return _load_dir(path, common_key) if path.is_dir() else _load_wad(path, common_key)


def profile_for(title):
    try:
        return PROFILES[(title.title_id, title.version)]
    except KeyError:
        raise ValueError('no patch profile for %s' % title.name) from None


def _fakesign(tmd):
    """Blank the signature and tune the unused word at 0x1E2 until the hash starts with 00."""
    tmd = bytearray(tmd)
    tmd[4:0x104] = b'\0' * 0x100
    for filler in range(0x10000):
        tmd[0x1E2:0x1E4] = struct.pack('>H', filler)
        if hashlib.sha1(tmd[0x140:]).digest()[0] == 0:
            return bytes(tmd)
    raise ValueError('could not fakesign the TMD')


def patch(title, profile):
    """A new Title with the driver edited, its TMD record updated and the TMD fakesigned."""
    # load() already checked every content against the TMD, so a stock TMD
    # means a stock title: the rollback WAD and the patch base are both clean.
    if hashlib.sha1(title.tmd).hexdigest() != profile.stock_tmd_sha1:
        raise ValueError('%s is not the stock copy this profile was made for' % title.name)
    records = _records(title.tmd)
    k = [r[0] for r in records].index(profile.content_id)
    driver = bytearray(title.contents[k])
    for offset, old, new in profile.edits:
        old, new = bytes.fromhex(old), bytes.fromhex(new)
        if driver[offset:offset + len(old)] != old:
            raise ValueError('expected %s at 0x%x of content %08x'
                             % (old.hex(), offset, profile.content_id))
        driver[offset:offset + len(new)] = new

    cid, index, _type, size, _sha1 = records[k]
    tmd = bytearray(title.tmd)
    o = RECORDS + RECORD * k
    # type 0x0001: a private copy in the title's own folder, not the shared pool
    tmd[o:o + 16] = struct.pack('>IHHQ', cid, index, 0x0001, size)
    tmd[o + 16:o + 36] = hashlib.sha1(driver).digest()

    contents = list(title.contents)
    contents[k] = bytes(driver)
    return Title(title.certs, title.ticket, _fakesign(tmd), contents, title.title_key)


def pack_wad(title):
    """The title as an installable WAD, laid out as the standard tools do."""
    def pad(b):
        return b + b'\0' * (-len(b) % 64)

    key = title.title_key
    data = b''.join(
        pad(_aes('-e', key, _content_iv(r[1]), content))
        for r, content in zip(_records(title.tmd), title.contents))
    header = struct.pack('>I2sHIIIIII', 0x20, b'Is', 0, len(title.certs), 0,
                         len(title.ticket), len(title.tmd), len(data), 0)
    return pad(header) + pad(title.certs) + pad(title.ticket) + pad(title.tmd) + data


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    key_file = None
    if argv[:1] == ['--key'] and len(argv) >= 2:
        key_file, argv = pathlib.Path(argv[1]), argv[2:]
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    source, out = pathlib.Path(argv[0]), pathlib.Path(argv[1])
    try:
        if key_file is None:
            key_file = next((pathlib.Path(n) for n in DEFAULT_KEY_FILES if pathlib.Path(n).is_file()),
                            None)
            if key_file is None:
                raise ValueError('no Wii common key: pass --key, or put common-key.bin or '
                                 "BootMii's keys.bin in the current folder")
        title = load(source, read_common_key(key_file))
        patched = patch(title, profile_for(title))
        wads = [(title.name + '.wad', pack_wad(title)),
                (title.name + '-ax88772bc.wad', pack_wad(patched))]
    except (ValueError, OSError, struct.error, subprocess.CalledProcessError) as e:
        print('error: %s' % e, file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    for name, wad in wads:
        (out / name).write_bytes(wad)
        print('%s  %s' % (hashlib.md5(wad).hexdigest(), out / name))
    return 0


if __name__ == '__main__':
    sys.exit(main())
