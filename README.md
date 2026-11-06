# Wii Ethernet patch for AX88772B/C adapters

The Wii's USB Ethernet driver only works with the original ASIX AX88772
(the chip in Nintendo's RVL-015 adapter). Almost every cheap USB LAN adapter
sold today uses the newer AX88772B or AX88772C, which the Wii does not
detect. This tool patches the driver inside the Wii's own system software so
a B or C adapter works.

**Status: working on a real console.** Tested on a Wii (RVL-001, Wii Menu
4.3U) with an AX88772C adapter (USB id `0b95:772b`, revision 0002). With both
patches installed, Wii Settings' wired connection test passes, the Homebrew
Channel gets an IP address, and apps and games sent with wiiload start over
the wire. See "Tested on hardware".

It is one Python file with no dependencies beyond Python 3 and `openssl`.

> **Use at your own risk.** This installs a modified IOS. The slot-80 patch
> replaces the IOS the Wii Menu runs on; if it goes wrong, only BootMii
> installed as boot2 and a NAND backup can recover the console. Read
> "Before you install" first.

## Why the adapter fails

The driver is a module inside each IOS (the Wii's system software; the
Homebrew Channel runs on IOS58). It fails on a B or C chip for two reasons:

| | Stock driver | B/C chip |
|---|---|---|
| USB id it opens | `0b95:7720` | reports `0b95:772b` (C = revision 0002) |
| RX Control it writes | `0x318` or `0x218` | bit 9 (`0x200`) now picks a header format, which misaligns every received packet; needs `0x118` |

Changing only the id (in the driver, or by reflashing the adapter's EEPROM)
is not enough for a B or C chip. The D and E chips (USB id `0b95:1790`) are a
different design and cannot be made to work this way.

To check which chip you have, plug the adapter into a computer and read its
USB id (`lsusb` on Linux; System Information → USB on a Mac).

## Two drivers

Each IOS carries its own copy of the driver, and two of them matter:

| IOS | Who runs on it | Driver | Supported files |
|---|---|---|---|
| IOS58 v6176 | Homebrew Channel, wiiload, most homebrew | newer Thumb build, 11,516 bytes | stock IOS58 v6176 |
| slot 80 | Wii Menu 4.3, Wii Settings and its connection test | older ARM build, 30,584 bytes | stock IOS80 v6944, and ModMii's `IOS80v65535(ModMii-IOS60-v6174).wad` (same driver binary) |

Patching IOS58 alone is not enough. A wired connection only becomes the
active one when Wii Settings' connection test passes, and that test runs on
slot 80. Unpatched, it fails with error 51420 or 51422 ("no LAN adapter"),
no connection is active, and the Homebrew Channel shows "Network not
initialized".

## What the IOS58 patch changes

Four edits to IOS58 v6176's Ethernet driver (content id `00000016`, 11,516
bytes, SHA-1 `cc776639562ba298d66598efe0340b4255bf4b6c`). Four bytes change
(the driver then adds `0x80`, "start", to the RX Control value before writing
it):

| Offset | Stock | Patched | Meaning |
|---|---|---|---|
| `0x1BC0` | `0b95 7720` | `0b95 772b` | USB id the driver asks for |
| `0x18DC` | `movs r1,#0xC6; lsls r1,#2` | `movs r1,#0x46; lsls r1,#2` | RX Control `0x318` → `0x118` |
| `0x18F8` | `movs r1,#0x86; lsls r1,#2` | `movs r1,#0x46; lsls r1,#2` | RX Control `0x218` → `0x118` |
| `0x1A3E` | `movs r1,#0x4C` | `movs r1,#0xCC` | reset on shutdown: keep the oscillator running |

The stock driver already has a third path that writes `0x118`, so after the
patch all three agree. The driver's entry in the title's contents list (the
TMD) gets the new checksum and becomes a private content, and the TMD is
fakesigned. The ticket and every other content are untouched.

After the patch the genuine Nintendo adapter (original AX88772) is no longer
recognised: this replaces the id, it does not add one.

## What the slot-80 patch changes

Nine edits, 21 bytes, to the ARM driver (content id `0000000a`, SHA-1
`aa6b000147dd12c838e40e58b25d3f5f510585f8`). The same count the vWii
patcher's author reported for this driver.

| Offset | Stock | Patched | Meaning |
|---|---|---|---|
| `0x6DDE` | `/dev/usb/ehc/0b95/7720` | `…/772b` | device path it opens (high speed) |
| `0x6E5A` | `/dev/usb/oh0/0b95/7720` | `…/772b` | device path it opens (full speed) |
| `0x23F4` | `add r3, r3, #0x20` | `add r3, r3, #0x2b` | product id handed to the USB stack |
| `0x1FE4` | `mov ip,#0xb900000; add ip,#0x57000; add ip,#0x720` | `ldr ip,[pc]; b +0; .word 0x0b95772b` | id the device-list scanner looks for (`0x772b` does not fit ARM immediates) |
| `0x1108` | `mov r1, #0x18` | `mov r1, #0x118` | RX Control, 2048-byte buffers |
| `0x1354` | `mov r1, #0x218` | `mov r1, #0x118` | RX Control, 8192-byte buffers |
| `0x118C` | `mov r1, #0x318` | `mov r1, #0x118` | RX Control, 16384-byte buffers |
| `0x1330` | `mov r1, #0x44` | `mov r1, #0xC4` | reset on start: keep the oscillator running |
| `0x15D8` | `mov r1, #0x4C` | `mov r1, #0xCC` | reset on shutdown: same |

## What you need

- **Python 3 and `openssl`** on the computer that builds the WADs.
- **The Wii common key.** It is not included here. Point the tool at either
  a 16-byte `common-key.bin` or the `keys.bin` BootMii writes next to a NAND
  backup of your own console (the key sits at offset `0x114`). The tool
  checks the key's SHA-1 before it uses it, so a wrong file is refused.
- **The IOS to patch**, as a `.wad` or as a folder in the update server's
  layout (`tmd`, `cetk`, one file per content id). Nintendo's update server
  still serves both titles: `http://nus.cdn.shop.wii.com/ccs/download/<title id>/`
  with `tmd`, `cetk` and each content id from the TMD (`000000010000003a`
  for IOS58, `0000000100000050` for IOS80). NUS downloaders do this for you.
  ModMii's slot-80 file is on the SD card after ModMii's wizard, in `WAD/`.

## Use

    python3 wii_eth.py [--key FILE] <IOS> <output folder>

Without `--key` it looks for `common-key.bin`, then `keys.bin`, in the
current folder. It writes two files, the stock WAD (for rollback) and the
patched one, and prints their MD5:

| File | MD5 | |
|---|---|---|
| `IOS58-64-v6176.wad` | `8ab886c3b1847769afdc51a6a113ff6d` | stock, for rollback; the same bytes ModMii's database lists |
| `IOS58-64-v6176-ax88772bc.wad` | `7fbdb7bf5fa698ab0b3fdb297914ac19` | patched |
| `IOS80-64-v6944.wad` | `85bc6aaafebfe2f5ff5cec3bab113555` | stock, for rollback |
| `IOS80-64-v6944-ax88772bc.wad` | `caacde6cea6c992e7fbe00e31fc50e41` | patched, from stock IOS80 v6944 |
| `IOS80-64-v65535-ax88772bc.wad` | `e987f5b8e73cd8160c2042f1b0999f6d` | patched, from ModMii's slot-80 file (keep ModMii's own file for rollback) |

The stock WAD rebuilt from a ModMii file differs from ModMii's own by one
header byte (ModMii's data-size field leaves out the last content's
padding); both install the same title.

It refuses, and writes nothing, for: an IOS it has no profile for; a copy
whose contents list (TMD) is not Nintendo's stock one, so a dump of an
already-modified IOS can never become the "stock" rollback file; a content
that fails its checksum; an edit whose old bytes are not where they should
be; and a missing or wrong common key.

Do not share the WADs or any IOS content: they are Nintendo's files.

## Before you install

1. Find out what is on the Wii: Wii Menu version, Homebrew Channel,
   Priiloader, BootMii, and which IOS58 the HackMii installer reports.
2. Make a NAND backup with BootMii and keep a copy off the SD card.
3. Have a way to start homebrew that does not go through the Homebrew
   Channel: BootMii (as boot2 if this console allows it, otherwise as an
   IOS) or a WAD manager set as Priiloader's installed file.
4. For the slot-80 patch, **BootMii must be installed as boot2**. Check with
   the HackMii installer.

## Installing the IOS58 patch

1. Copy both IOS58 WADs to the SD card's WAD folder.
2. Install `IOS58-64-v6176-ax88772bc.wad` with a WAD manager that can install
   a fakesigned IOS from the Homebrew Channel (YAWM ModMii Edition works).
3. Plug in the adapter and start the Homebrew Channel. It may draw upside
   down: people who patched IOS58 on vWii and on a Wii report that, and it is
   cosmetic.

**Rollback:** install `IOS58-64-v6176.wad` the same way, from the Homebrew
Channel if it still starts, otherwise from the route in "Before you
install", step 3.

IOS58 is not the Wii Menu's IOS (on 4.3 that is slot 80), so a bad IOS58
cannot stop the console booting; the worst case is a Homebrew Channel that
does not start, which the stock WAD or the NAND backup undoes.

Do not reinstall the Homebrew Channel from the HackMii installer while IOS58
is patched: the installer refuses the fakesigned IOS58 and ties the channel
to IOS61, whose driver is stock.

## Installing the slot-80 patch

This is the IOS the Wii Menu and Priiloader run on. If it is bad, neither
starts, so it needs BootMii installed as boot2 and the SD card (with its
`bootmii` folder and the NAND backup) in the console at power-on.

1. Install the patched slot-80 WAD that matches what is on the console
   (`IOS80-64-v65535-ax88772bc.wad` after ModMii's wizard, otherwise
   `IOS80-64-v6944-ax88772bc.wad`) with YAWM ModMii Edition.
2. Power off, plug in the adapter and cable, power on with the SD card in.
3. Wii Settings → Internet → Connection Settings → a slot → Wired
   Connection, save, run the test.
4. Start the Homebrew Channel: the top-left shows the console's IP address
   once the network is up.

**Rollback:** from BootMii, start the Homebrew Channel and install the stock
slot-80 WAD (ModMii's own file, or `IOS80-64-v6944.wad`) with YAWM, or
restore the NAND backup.

## Tested on hardware

On 2026-11-05: Wii RVL-001 on Wii Menu 4.3U, adapter `0b95:772b` revision
0002 (product string "AX88772C"), with ModMii's slot-80 file patched.

- **Slot-80 patch:** the wired connection test in Wii Settings passed and the
  adapter's link lights came on. Before it, the test failed with 51420/51422.
- **IOS58 patch:** the Homebrew Channel (Home menu: IOS58 v24.32) showed an
  IP address in its top-left corner.
- **Link quality:** pings answered 100% at every size up to 1472 bytes and
  every spacing; 45 full-size packets back to back all answered.
- **App launch:** YAWM ModMii Edition sent with wiiload started on the Wii.
- **Game launch:** USB Loader GX 4.0 r1283 sent with wiiload and the
  arguments `--ios=249 --bootios=58 --usbport=0 --sdmode=1 <game ID>` booted
  the game from the SD card with no menu in between, and with `--sdmode=0`
  from an NTFS hard drive. The drive has to be on the USB port the loader
  calls 0 and the adapter on the other.

The stock IOS80 v6944 patch makes the same 21 driver edits but has not been
installed on a console.

## wiiload notes

For anyone sending apps or games to the Homebrew Channel over the wire:

- **wiiload** is TCP 4299: 16-byte header (`HAXX`, version 0 5, u16 argument
  length, u32 compressed length, u32 uncompressed length), then the
  zlib-compressed `.dol`, then the arguments, each NUL-terminated, the first
  being the file name.
- **A network launch ignores the app's `meta.xml`**, so its `<arguments>`
  must be sent explicitly.
- **USB Loader GX boots a game directly** when any argument is six characters
  long with no `=` or `-` (four characters for a channel). `--sdmode=` is
  only honoured when its settings live on the SD card.
- **Most transfers pause until about 10 seconds after the connection opens**,
  then run at about 1.3 MB/s (two of nine ran with no pause). During the
  pause the Wii answers pings and has acknowledged the first 32 KB, but is
  not reading the socket. Pacing the send, a small send buffer and waiting
  after the header do not avoid it, and the cause is unknown. Use a timeout
  of at least 60 seconds.
- **The Homebrew Channel resets the connection** once it holds the whole
  push. Waiting for that reset (rather than for the local send buffer to
  drain) tells a sender the transfer really arrived.
- **An unfinished transfer leaves an error box** on the Homebrew Channel, and
  it accepts nothing until A is pressed. Sixteen bytes that are not a valid
  header are dropped silently, which makes a safe liveness probe.

## Wii U

Wii U mode needs a different fix: the `wafel_ax88772b` plugin
(`5usbeth.ipx` in `/wiiu/ios_plugins`), which a tester confirmed with a C
chip. It needs ISFShax and stroopwafel 1.2 or later. vWii mode has its own
IOS files and would need this patch made for those versions.

## Tests

    uv run --with pytest pytest -q

(or `python3 -m pytest -q` with pytest installed). The fixtures are made up:
a fake title encrypted under a made-up common key. More tests run against
real files when `WII_COMMON_KEY` names a key file and one of these is set:

- `WII_IOS58_DIR` (IOS58 v6176 in the update-server layout): the stock WAD
  must match the reference MD5, the patch must change exactly the four bytes
  above, and the patched WAD must have the MD5 in the table.
- `WII_IOS80_DIR` (stock IOS80 v6944) or `WII_MODMII_IOS80` (ModMii's WAD):
  the slot-80 patch must change exactly the 21 bytes above.

## Credits and sources

- GBAtemp, "AX88772B/C/D USB Ethernet Patcher for vWii" (thread 680252): the
  patch list and the reports from real consoles.
- GBAtemp, "We can now use the AX88772B on the Wii U" (thread 670646).
- `StroopwafelCFW/wafel_ax88772b`: the register fix, by chip code.
- `urbanshadow/Wii-Ethernet-Patcher` (archived, no licence): the byte
  patterns. No code from it is used here.
- The Linux `asix` driver, for the RX Control bit names.

## Licence

MIT, see `LICENSE`. The licence covers this tool only; it grants nothing over
Nintendo's software, which you supply yourself.
