"""Tests for wii_eth.py.

Every fixture here is made up: a fake title with fake certificates and filler
contents, encrypted the way a real one is, under a made-up common key. No
Nintendo bytes or keys live in the repo. The tests at the bottom run against
real files only when WII_COMMON_KEY and WII_IOS58_DIR, WII_IOS80_DIR or
WII_MODMII_IOS80 point at them (see README.md).
"""
import dataclasses
import hashlib
import os
import pathlib
import struct
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import wii_eth  # noqa: E402

# The test's own crypto and constants, so nothing below is checked against the
# code under test's idea of the format.
COMMON_KEY = '0f1e2d3c4b5a69788796a5b4c3d2e1f0'  # made up, not the Wii's
KEY = bytes.fromhex(COMMON_KEY)
TITLE_ID = bytes.fromhex('00000001000000fe')
VERSION = 1234
TITLE_KEY = bytes(range(16))


def _aes(mode, key_hex, iv_hex, data):
    data += b'\0' * (-len(data) % 16)
    return subprocess.run(
        ['openssl', 'enc', mode, '-aes-128-cbc', '-nopad', '-K', key_hex, '-iv', iv_hex],
        input=data, capture_output=True, check=True).stdout


def _filler(n, seed):
    return bytes((i * seed + 3) & 0xFF for i in range(n))


def _eth_content():
    b = bytearray(_filler(0x1F3, 7))  # not a multiple of 16
    b[0x40:0x48] = bytes.fromhex('0b95772000ffffff')
    b[0x80:0x84] = bytes.fromhex('21c60089')
    b[0x90:0x94] = bytes.fromhex('21860089')
    b[0xA0:0xA2] = bytes.fromhex('214c')
    return bytes(b)


def _trap_content():
    b = bytearray(_filler(100, 11))
    b[0x10:0x14] = bytes.fromhex('21860089')  # same bytes as an ETH edit site
    return bytes(b)


# (content id, index, type, plaintext). The indexes skip numbers so a content's
# index is never its position, and the 100-byte one sits mid-file so the
# 64-byte alignment between contents is exercised.
CONTENTS = [
    (0x30, 0, 0x0001, b'\xAA' * 64),
    (0x06, 2, 0x8001, _trap_content()),
    (0x16, 5, 0x8001, _eth_content()),
]
ETH = 2  # the driver's position in CONTENTS


def _cert(sig_type, name):
    size, name_off = (0x400, 0x284) if sig_type == 0x10000 else (0x300, 0x184)
    b = bytearray(_filler(size, len(name)))
    b[0:4] = struct.pack('>I', sig_type)
    b[name_off:name_off + 0x40] = name.encode().ljust(0x40, b'\0')
    return bytes(b)


CA = _cert(0x10000, 'CA00000001')
CP = _cert(0x10001, 'CP00000004')
XS = _cert(0x10001, 'XS00000003')


def _tmd():
    b = bytearray(0x1E4 + 36 * len(CONTENTS))
    b[0:4] = struct.pack('>I', 0x10001)
    b[4:0x104] = b'\x5A' * 0x100
    b[0x140:0x180] = b'Root-CA00000001-CP00000004'.ljust(0x40, b'\0')
    b[0x18C:0x194] = TITLE_ID
    b[0x1DC:0x1E2] = struct.pack('>HHH', VERSION, len(CONTENTS), 0)
    for k, (cid, idx, typ, data) in enumerate(CONTENTS):
        o = 0x1E4 + 36 * k
        b[o:o + 16] = struct.pack('>IHHQ', cid, idx, typ, len(data))
        b[o + 16:o + 36] = hashlib.sha1(data).digest()
    return bytes(b)


def _ticket():
    b = bytearray(_filler(0x2A4, 5))
    b[0:4] = struct.pack('>I', 0x10001)
    b[0x140:0x180] = b'Root-CA00000001-XS00000003'.ljust(0x40, b'\0')
    b[0x1BF:0x1CF] = _aes('-e', COMMON_KEY, TITLE_ID.hex() + '00' * 8, TITLE_KEY)
    b[0x1DC:0x1E4] = TITLE_ID
    return bytes(b)


def _encrypted(idx, data):
    return _aes('-e', TITLE_KEY.hex(), '%04x' % idx + '00' * 14, data)


@pytest.fixture(autouse=True)
def key_file(tmp_path, monkeypatch):
    """The made-up key as common-key.bin in the current folder, where main looks."""
    monkeypatch.setattr(wii_eth, 'COMMON_KEY_SHA1', hashlib.sha1(KEY).hexdigest())
    monkeypatch.chdir(tmp_path)
    f = tmp_path / 'common-key.bin'
    f.write_bytes(KEY)
    return f


@pytest.fixture
def nus_dir(tmp_path):
    """The fake title in the update server's layout: tmd, cetk, one file per content."""
    d = tmp_path / 'title'
    d.mkdir()
    (d / 'tmd').write_bytes(_tmd() + CP + CA)
    (d / 'cetk').write_bytes(_ticket() + XS + CA)
    for cid, idx, _typ, data in CONTENTS:
        (d / ('%08x' % cid)).write_bytes(_encrypted(idx, data))
    return d


@pytest.fixture
def profile():
    return wii_eth.Profile(
        title_id=int.from_bytes(TITLE_ID, 'big'), version=VERSION, content_id=0x16,
        stock_tmd_sha1=hashlib.sha1(_tmd()).hexdigest(),
        edits=((0x40, '0b957720', '0b95772b'),
               (0x80, '21c60089', '21460089'),
               (0x90, '21860089', '21460089'),
               (0xA0, '214c', '21cc')))


def _tamper(nus_dir):
    """Swap in a different first content and make the TMD agree with it: a title
    that is consistent, but not the stock one."""
    other = b'\xBB' * 64
    tmd = bytearray(_tmd())
    tmd[0x1E4 + 16:0x1E4 + 36] = hashlib.sha1(other).digest()
    (nus_dir / 'tmd').write_bytes(bytes(tmd) + CP + CA)
    (nus_dir / '00000030').write_bytes(_encrypted(0, other))


def _patched_eth():
    b = bytearray(_eth_content())
    b[0x43], b[0x81], b[0x91], b[0xA1] = 0x2B, 0x46, 0x46, 0xCC
    return bytes(b)


def _wad_sections(wad):
    """Split a WAD by its own header, the way an installer would."""
    hsize, typ, cert, _res, tik, tmd, data, footer = struct.unpack('>I2sxxIIIIII', wad[:32])
    up = lambda n: (n + 63) & ~63  # noqa: E731
    o = up(hsize)
    out = {'type': typ, 'footer': footer, 'data_size': data}
    for name, size in (('certs', cert), ('ticket', tik), ('tmd', tmd)):
        out[name] = wad[o:o + size]
        o += up(size)
    out['data'] = wad[o:]
    return out


# --- loading ---------------------------------------------------------------

def test_load_decrypts_every_content(nus_dir):
    title = wii_eth.load(nus_dir, KEY)
    assert title.contents == [data for _c, _i, _t, data in CONTENTS]
    assert (title.title_id, title.version) == (0x00000001000000FE, 1234)


def test_load_refuses_a_file_that_is_not_an_installable_wad(nus_dir, tmp_path):
    wad = bytearray(wii_eth.pack_wad(wii_eth.load(nus_dir, KEY)))
    wad[4:6] = b'ib'  # a boot2 WAD
    f = tmp_path / 'boot2.wad'
    f.write_bytes(bytes(wad))
    with pytest.raises(ValueError, match='installable'):
        wii_eth.load(f, KEY)


def test_load_refuses_a_content_that_fails_its_checksum(nus_dir):
    f = nus_dir / '00000016'
    raw = bytearray(f.read_bytes())
    raw[5] ^= 0xFF
    f.write_bytes(bytes(raw))
    with pytest.raises(ValueError, match='00000016'):
        wii_eth.load(nus_dir, KEY)


# --- patching --------------------------------------------------------------

def test_patch_changes_only_the_listed_bytes_of_the_driver(nus_dir, profile):
    patched = wii_eth.patch(wii_eth.load(nus_dir, KEY), profile)
    assert patched.contents[ETH] == _patched_eth()
    assert patched.contents[0] == CONTENTS[0][3]
    assert patched.contents[1] == _trap_content()  # same bytes elsewhere stay put


def test_patch_leaves_the_loaded_title_untouched(nus_dir, profile):
    title = wii_eth.load(nus_dir, KEY)
    wii_eth.patch(title, profile)
    assert title.contents[ETH] == _eth_content()
    assert title.tmd == _tmd()


def test_patch_refuses_a_title_that_is_not_the_stock_one(nus_dir, profile):
    _tamper(nus_dir)
    title = wii_eth.load(nus_dir, KEY)  # consistent with its own TMD, so it loads
    with pytest.raises(ValueError, match='stock'):
        wii_eth.patch(title, profile)


def test_patch_refuses_an_edit_whose_old_bytes_are_not_there(nus_dir, profile):
    title = wii_eth.load(nus_dir, KEY)
    wrong = dataclasses.replace(profile, edits=((0x44, '0b957720', '0b95772b'),))
    with pytest.raises(ValueError, match='0x44'):
        wii_eth.patch(title, wrong)


def test_patched_tmd_carries_the_new_checksum_as_a_private_content(nus_dir, profile):
    patched = wii_eth.patch(wii_eth.load(nus_dir, KEY), profile)
    stock = _tmd()
    rec = 0x1E4 + 36 * ETH  # the driver's record
    cid, idx, typ, size = struct.unpack('>IHHQ', patched.tmd[rec:rec + 16])
    assert (cid, idx, typ, size) == (0x16, 5, 0x0001, 0x1F3)
    assert patched.tmd[rec + 16:rec + 36] == hashlib.sha1(_patched_eth()).digest()
    # the other two records are byte-for-byte the stock ones
    assert patched.tmd[0x1E4:rec] == stock[0x1E4:rec]
    assert len(patched.tmd) == len(stock) == rec + 36


def test_patched_tmd_is_fakesigned(nus_dir, profile):
    patched = wii_eth.patch(wii_eth.load(nus_dir, KEY), profile)
    assert patched.tmd[4:0x104] == b'\0' * 0x100
    assert hashlib.sha1(patched.tmd[0x140:]).digest()[0] == 0
    # only the signature, the filler word and the driver's record may differ
    stock = _tmd()
    assert patched.tmd[0:4] == stock[0:4]
    assert patched.tmd[0x104:0x1E2] == stock[0x104:0x1E2]


def test_profile_lookup_refuses_an_unknown_title(nus_dir):
    with pytest.raises(ValueError, match='v1234'):
        wii_eth.profile_for(wii_eth.load(nus_dir, KEY))


# --- WAD packing -----------------------------------------------------------

def test_pack_wad_lays_out_the_sections_an_installer_expects(nus_dir):
    wad = wii_eth.pack_wad(wii_eth.load(nus_dir, KEY))
    s = _wad_sections(wad)
    assert wad[:64] == struct.pack('>I2sHIIIIII', 0x20, b'Is', 0, 0xA00, 0, 0x2A4,
                                   0x250, 704, 0) + bytes(32)
    # sections start on 64-byte boundaries and the gaps are zeros
    assert wad[0x40:0xA40] == s['certs']
    assert wad[0xA40:0xCE4] == s['ticket'] and wad[0xCE4:0xD00] == bytes(0x1C)
    assert wad[0xD00:0xF50] == s['tmd'] and wad[0xF50:0xF80] == bytes(0x30)
    assert s['certs'] == CA + CP + XS
    assert s['ticket'] == _ticket()
    assert s['tmd'] == _tmd()
    assert s['footer'] == 0
    assert s['data_size'] == len(s['data']) == 64 + 128 + 512
    assert len(wad) % 64 == 0


def test_pack_wad_stores_each_content_encrypted_at_a_64_byte_boundary(nus_dir):
    s = _wad_sections(wii_eth.pack_wad(wii_eth.load(nus_dir, KEY)))
    o = 0
    for _cid, idx, _typ, data in CONTENTS:
        enc = s['data'][o:o + ((len(data) + 15) & ~15)]
        plain = _aes('-d', TITLE_KEY.hex(), '%04x' % idx + '00' * 14, enc)
        assert plain[:len(data)] == data
        o += (len(data) + 63) & ~63


def test_a_packed_wad_loads_back_the_same(nus_dir, tmp_path):
    title = wii_eth.load(nus_dir, KEY)
    f = tmp_path / 'out.wad'
    f.write_bytes(wii_eth.pack_wad(title))
    again = wii_eth.load(f, KEY)
    assert again.contents == title.contents
    assert (again.tmd, again.ticket, again.certs) == (title.tmd, title.ticket, title.certs)


# --- the common key --------------------------------------------------------

def test_read_common_key_takes_a_16_byte_key_file(key_file):
    assert wii_eth.read_common_key(key_file) == KEY


def test_read_common_key_takes_a_bootmii_keys_bin(tmp_path):
    blob = bytearray(_filler(0x400, 13))
    blob[0x114:0x124] = KEY
    f = tmp_path / 'keys.bin'
    f.write_bytes(bytes(blob))
    assert wii_eth.read_common_key(f) == KEY


@pytest.mark.parametrize('blob', [bytes(16), bytes(15), bytes(0x400)])
def test_read_common_key_refuses_anything_else(tmp_path, blob):
    f = tmp_path / 'wrong.bin'
    f.write_bytes(blob)
    with pytest.raises(ValueError, match='wrong.bin'):
        wii_eth.read_common_key(f)


def test_main_uses_the_key_file_it_is_given(nus_dir, tmp_path, key_file, profile, monkeypatch):
    monkeypatch.setitem(wii_eth.PROFILES, (profile.title_id, profile.version), profile)
    elsewhere = tmp_path / 'keys' / 'my-key.bin'
    elsewhere.parent.mkdir()
    key_file.rename(elsewhere)
    assert wii_eth.main(['--key', str(elsewhere), str(nus_dir), str(tmp_path / 'out')]) == 0


def test_main_falls_back_to_keys_bin(nus_dir, tmp_path, key_file, profile, monkeypatch):
    monkeypatch.setitem(wii_eth.PROFILES, (profile.title_id, profile.version), profile)
    blob = bytearray(0x400)
    blob[0x114:0x124] = KEY
    (tmp_path / 'keys.bin').write_bytes(bytes(blob))
    key_file.unlink()
    assert wii_eth.main([str(nus_dir), str(tmp_path / 'out')]) == 0


def test_main_writes_nothing_without_a_key(nus_dir, tmp_path, key_file, capsys):
    key_file.unlink()
    out = tmp_path / 'out'
    assert wii_eth.main([str(nus_dir), str(out)]) == 1
    assert not out.exists()
    assert '--key' in capsys.readouterr().err


def test_main_writes_nothing_with_the_wrong_key(nus_dir, tmp_path, key_file, capsys):
    key_file.write_bytes(bytes(range(16)))
    out = tmp_path / 'out'
    assert wii_eth.main([str(nus_dir), str(out)]) == 1
    assert not out.exists()
    assert 'common key' in capsys.readouterr().err


# --- command line ----------------------------------------------------------

def test_main_writes_a_stock_wad_and_a_patched_wad(nus_dir, tmp_path, profile, monkeypatch):
    monkeypatch.setitem(wii_eth.PROFILES, (profile.title_id, profile.version), profile)
    out = tmp_path / 'out'
    assert wii_eth.main([str(nus_dir), str(out)]) == 0
    stock = wii_eth.load(out / 'IOS254-64-v1234.wad', KEY)
    patched = wii_eth.load(out / 'IOS254-64-v1234-ax88772bc.wad', KEY)
    assert stock.contents[ETH] == _eth_content()
    assert stock.tmd == _tmd()
    assert patched.contents[ETH] == _patched_eth()


def test_main_gives_the_same_patched_wad_from_a_wad_as_from_a_folder(
        nus_dir, tmp_path, profile, monkeypatch):
    monkeypatch.setitem(wii_eth.PROFILES, (profile.title_id, profile.version), profile)
    assert wii_eth.main([str(nus_dir), str(tmp_path / 'a')]) == 0
    stock_wad = tmp_path / 'a' / 'IOS254-64-v1234.wad'
    assert wii_eth.main([str(stock_wad), str(tmp_path / 'b')]) == 0
    name = 'IOS254-64-v1234-ax88772bc.wad'
    assert (tmp_path / 'b' / name).read_bytes() == (tmp_path / 'a' / name).read_bytes()


def test_main_writes_nothing_for_a_title_it_has_no_profile_for(nus_dir, tmp_path, capsys):
    out = tmp_path / 'out'
    assert wii_eth.main([str(nus_dir), str(out)]) == 1
    assert not out.exists()
    assert 'v1234' in capsys.readouterr().err


def test_main_writes_nothing_for_a_title_that_is_not_stock(
        nus_dir, tmp_path, profile, monkeypatch, capsys):
    monkeypatch.setitem(wii_eth.PROFILES, (profile.title_id, profile.version), profile)
    _tamper(nus_dir)
    out = tmp_path / 'out'
    assert wii_eth.main([str(nus_dir), str(out)]) == 1
    assert not out.exists()
    assert 'stock' in capsys.readouterr().err


@pytest.mark.parametrize('break_it', ['no source', 'no certificates', 'missing content',
                                      'short tmd'])
def test_main_reports_unreadable_input_as_an_error(nus_dir, tmp_path, capsys, break_it):
    source = nus_dir
    if break_it == 'no source':
        source = tmp_path / 'nope'
    elif break_it == 'no certificates':
        (nus_dir / 'tmd').write_bytes(_tmd())
    elif break_it == 'missing content':
        (nus_dir / '00000016').unlink()
    elif break_it == 'short tmd':
        (nus_dir / 'tmd').write_bytes(_tmd()[:0x100])
    out = tmp_path / 'out'
    assert wii_eth.main([str(source), str(out)]) == 1
    assert not out.exists()
    assert capsys.readouterr().err.startswith('error: ')


# --- the real IOS58 (only when a copy is on hand) ---------------------------

REAL_KEY = os.environ.get('WII_COMMON_KEY')
REAL_KEY_SHA1 = 'ebeae6d2762d4d3ea160a6d8327fac9a25f8062b'


def _real_key():
    return wii_eth.read_common_key(REAL_KEY, REAL_KEY_SHA1)


def _real_load(path):
    return wii_eth.load(pathlib.Path(path), _real_key())


REAL = os.environ.get('WII_IOS58_DIR')
real = pytest.mark.skipif(not (REAL and REAL_KEY),
                          reason='set WII_COMMON_KEY and WII_IOS58_DIR to a real IOS58 v6176')


@real
def test_real_stock_wad_matches_the_reference_checksum():
    # ModMii's database lists this MD5 for IOS58-64-v6176.wad
    wad = wii_eth.pack_wad(_real_load(REAL))
    assert hashlib.md5(wad).hexdigest() == '8ab886c3b1847769afdc51a6a113ff6d'


@real
def test_real_patched_wad_is_the_one_the_readme_names():
    title = _real_load(REAL)
    wad = wii_eth.pack_wad(wii_eth.patch(title, wii_eth.profile_for(title)))
    assert hashlib.md5(wad).hexdigest() == '7fbdb7bf5fa698ab0b3fdb297914ac19'


def _changed(title, patched):
    """{(content position, offset): (old byte, new byte)} for every byte that differs."""
    changed = {}
    for k, (a, b) in enumerate(zip(title.contents, patched.contents)):
        assert len(a) == len(b)
        for o, (x, y) in enumerate(zip(a, b)):
            if x != y:
                changed[(k, o)] = (x, y)
    return changed


@real
def test_real_patch_changes_exactly_the_four_driver_bytes():
    title = _real_load(REAL)
    patched = wii_eth.patch(title, wii_eth.profile_for(title))
    assert _changed(title, patched) == {
        (17, 0x18DD): (0xC6, 0x46),  # RX Control 0x318 -> 0x118
        (17, 0x18F9): (0x86, 0x46),  # RX Control 0x218 -> 0x118
        (17, 0x1A3F): (0x4C, 0xCC),  # reset: keep the oscillator running
        (17, 0x1BC3): (0x20, 0x2B),  # USB product id 7720 -> 772b
    }


# --- the System Menu's IOS on 4.3: the older ARM driver ----------------------
# Stock IOS80 v6944, and the file ModMii installs in slot 80 instead
# (IOS80v65535, built from IOS60 v6174). Both carry the same driver.

REAL80 = os.environ.get('WII_IOS80_DIR')
MODMII80 = os.environ.get('WII_MODMII_IOS80')


def _arm_driver_changes():
    def word(offset, old, new):
        return {(10, offset + i): (o, n)
                for i, (o, n) in enumerate(zip(bytes.fromhex(old), bytes.fromhex(new)))
                if o != n}

    want = {}
    # the two device paths the driver opens: .../0b95/7720 -> .../0b95/772b
    want.update(word(0x6DDE, '37373230', '37373262'))
    want.update(word(0x6E5A, '37373230', '37373262'))
    # the id it hands to the USB stack: add r3, r3, #0x20 -> #0x2b
    want.update(word(0x23F4, 'e2833020', 'e283302b'))
    # the device-list scanner: mov/add/add building 0x0b957720 becomes
    # ldr ip, [pc]; b +0; .word 0x0b95772b
    want.update(word(0x1FE4, 'e3a0c6b9e28cca57e28cce72', 'e59fc000ea0000000b95772b'))
    # RX Control for 2048, 8192 and 16384-byte buffers: all 0x118
    want.update(word(0x1108, 'e3a01018', 'e3a01f46'))
    want.update(word(0x1354, 'e3a01f86', 'e3a01f46'))
    want.update(word(0x118C, 'e3a01fc6', 'e3a01f46'))
    # both resets keep the oscillator running: 0x44 -> 0xC4, 0x4C -> 0xCC
    want.update(word(0x1330, 'e3a01044', 'e3a010c4'))
    want.update(word(0x15D8, 'e3a0104c', 'e3a010cc'))
    assert len(want) == 21
    return want


@pytest.mark.skipif(not (REAL80 and REAL_KEY),
                    reason='set WII_COMMON_KEY and WII_IOS80_DIR to a real IOS80 v6944')
def test_real_ios80_patch_changes_exactly_the_known_driver_bytes():
    title = _real_load(REAL80)
    patched = wii_eth.patch(title, wii_eth.profile_for(title))
    assert _changed(title, patched) == _arm_driver_changes()


@pytest.mark.skipif(not (MODMII80 and REAL_KEY),
                    reason="set WII_COMMON_KEY and WII_MODMII_IOS80 to ModMii's IOS80v65535 WAD")
def test_modmii_ios80_patch_changes_exactly_the_known_driver_bytes():
    title = _real_load(MODMII80)
    assert (title.title_id, title.version) == (0x0000000100000050, 65535)
    patched = wii_eth.patch(title, wii_eth.profile_for(title))
    assert _changed(title, patched) == _arm_driver_changes()
    # every other content record in the TMD is untouched
    rec = 0x1E4 + 36 * 10
    assert patched.tmd[0x1E4:rec] == title.tmd[0x1E4:rec]
    assert patched.tmd[rec + 36:] == title.tmd[rec + 36:]
