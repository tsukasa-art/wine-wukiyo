# Swingby Wine (`swingby-wine`)

[日本語](README.ja.md)

**Swingby Wine** (repository: `swingby-wine`) is the public Wine fork used by **Melammu**, the private
launcher at the core of [Orrery](https://tsukasa-art.com/projects/orrery/).
Orrery is a compatibility and library project for running Windows visual
novels as Mac applications without modifying the games themselves.

The fork is based directly on the [WineHQ](https://gitlab.winehq.org/wine/wine)
**Wine 10.0 release** (`b0738596`). This repository is the canonical source for
its Wine-side macOS and Rosetta compatibility patches. Runtime selection,
packaging, signing, and release policy belong to the private Melammu project;
the launcher and its release artifacts are not published here.

The fork credits [Sikarugir](https://github.com/Sikarugir-App/Sikarugir) as
macOS Wine prior art. One executable-memory change is an attributed conceptual
port and non-verbatim reimplementation, not copied Sikarugir source. The exact
provenance boundary is recorded in [SWINGBY_PATCHES.md](SWINGBY_PATCHES.md).

## What this fork demonstrates

| Area | Work in this repository |
|---|---|
| 32-bit execution on Apple Silicon | Rosetta-aware work in `wow64cpu` and executable-memory handling in `ntdll` |
| macOS window and presentation behavior | Changes in `winemac.drv`, `win32u`, DirectDraw, and WineD3D |
| Media and audio compatibility | Selected work in Quartz, WineGStreamer, DXVA2, DirectSound, and CoreAudio paths |
| Isolated title or engine behavior | Explicit default-off gates such as `MELAMMU_CMVS_THUMBS` |
| Patch provenance | A ledger separating WineHQ backports, attributed ports, and original fork changes |

Compatibility claims remain limited to the title, version, launch route, and
runtime that were actually verified. This repository provides Wine source and
build instructions, not a packaged Melammu release.

The public [melammu-vn](https://github.com/tsukasa-art/melammu-vn) repository is
a source-only reference implementation extracted from Melammu. It exposes a
curated SwiftUI library UI and generic engine detection; it is not the complete
launcher, a runtime bundle, or a public release of Melammu.

**[Swingby DXVK](https://github.com/tsukasa-art/swingby-dxvk)** (repository: `swingby-dxvk`) is a sibling public
fork, following the same model for a DXVK 2.4.1 base with MoltenVK/Apple
Silicon compatibility patches.

## Runtime dependency

x86→ARM translation currently relies on Rosetta 2. How long it stays available on Apple Silicon — and on what terms — is an open question, so reducing this dependency is a known long-term concern, not a solved one.

## Patches

### Core runtime patches

The supported Melammu runtime carries macOS/Rosetta compatibility work in
`wow64cpu`, `ntdll`, `win32u`, and `winemac.drv`. These are not launcher
features; they are Wine behavior fixes and belong in this fork.

### `d3d9` / `wined3d` — CMVS thumbnail capture

CMVS save/load thumbnails are gated by `MELAMMU_CMVS_THUMBS` and must remain
default-off for non-CMVS engines.

The current mechanism serves the last-presented frame to back-buffer
`LockRect(READONLY)` calls and uses Melammu-provided snapshot files only through
the documented launcher/Wine IPC contract.

Snap file format:

```text
[u32 width][u32 height][u32 stride] + BGRA pixels (top-down)
```

**Affected files**: `dlls/d3d9/*`, `dlls/wined3d/swapchain.c`

## Branches

Only `master` is the canonical integration branch. The other public refs preserve
reviewable experiment or recovery history; they are not alternate runtime bundles.

| Branch | Role | Status |
|---|---|---|
| `master` | Supported Melammu Wine patch set based on the WineHQ Wine 10.0 release | **Canonical.** Integrate maintained changes here; this Wine fork follows the upstream `master` convention rather than `main`. |
| `quartz-dsound-startup-avsync` | Experimental media/audio work around DirectSound preroll, WineGStreamer queueing, build provenance, and related diagnostics | **Mixed experiment history.** It contains ideas that were adopted, superseded thumbnail work, and unresolved WIP. Review commits individually; do not merge or bundle the branch wholesale. |
| `quartz-vmr9-image-presenter` | Historical movie-presentation investigation | **Contained in `master`.** The branch name records the initial VMR9 hypothesis; verification moved the fix path to VMR7 presenter rectangles, window retargeting, and graph-lock handling. Retained as a milestone, not an active development line. |
| `backup/pre-purge-master-fa93c4d-2026-06-15` | Snapshot of the pre-rehabilitation `master` | **Recovery reference only.** No active development takes place on this branch. |

Verified at: 2026-07-22 (`git ls-remote --heads origin` and ancestry checks against
`origin/master`).

## Build (macOS / Rosetta 2)

Requires Xcode Command Line Tools and x86_64 Homebrew (`/usr/local/bin/brew`).

```bash
mkdir build && cd build
arch -x86_64 env \
  PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/share/pkgconfig \
  LDFLAGS="-L/usr/local/lib" CPPFLAGS="-I/usr/local/include" \
  ../configure -C --enable-win64 --with-mingw \
  BISON=/usr/local/opt/bison/bin/bison
arch -x86_64 make -s -j$(sysctl -n hw.activecpu)
```

Produces x86_64 binaries that run under Rosetta 2.

## Integration boundary

The build produces Wine artifacts, not a ready-to-run Melammu application.
Integrators must keep PE and Unix-side modules ABI-matched, record source
revisions and artifact hashes, and apply their own signing and distribution
policy. Private Melammu scripts, bundle paths, and title-specific deployment
procedures are intentionally not presented as public instructions.

## Current graphics-runtime model

Renderer selection is title- and engine-specific in the private launcher:

- Wine's built-in **WineD3D / OpenGL** route remains the baseline for many D3D9
  and DirectDraw paths.
- **DXVK -> Vulkan -> MoltenVK -> Metal** is selected only for routes where it
  has been verified. It is not a blanket replacement for WineD3D.
- Mixed routes can keep D3D9 or DirectDraw on WineD3D while using DXVK for
  D3D11. The launcher owns renderer policy; this repository owns the Wine-side
  patches and default-off gates.

Apple D3DMetal / Game Porting Toolkit components are not part of the current
runtime described by this repository.

## Related

- [Orrery](https://tsukasa-art.com/projects/orrery/) — project overview
- [Orrery Case Notes](https://tsukasa-art.com/projects/orrery/#research-notes-title) — public compatibility investigations with private operational details removed
- [Swingby DXVK](https://github.com/tsukasa-art/swingby-dxvk) — public DXVK fork with MoltenVK/Apple Silicon compatibility work
- [melammu-vn](https://github.com/tsukasa-art/melammu-vn) — source-only public reference implementation
- [Zenn series, part 1](https://zenn.dev/tsukasa_art/articles/mac-eroge-compat-part1) — entry point to the series, not evidence of the current runtime state
- [Zenn: Reorganizing Wukiyo as Orrery](https://zenn.dev/tsukasa_art/articles/melammu-wukiyo-bridge) — project reorganization and series map, not evidence of the current runtime state
- [Sikarugir](https://github.com/Sikarugir-App/Sikarugir) — credited macOS Wine prior art

---

# Upstream Wine documentation

The remaining sections are retained from the WineHQ README. The fork-specific
overview, build notes, patch boundary, and Orrery links are above.

## INTRODUCTION

Wine is a program which allows running Microsoft Windows programs
(including DOS, Windows 3.x, Win32, and Win64 executables) on Unix.
It consists of a program loader which loads and executes a Microsoft
Windows binary, and a library (called Winelib) that implements Windows
API calls using their Unix, X11 or Mac equivalents.  The library may also
be used for porting Windows code into native Unix executables.

Wine is free software, released under the GNU LGPL; see the file
LICENSE for the details.


## QUICK START

From the top-level directory of the Wine source (which contains this file),
run:

```
./configure
make
```

Then either install Wine:

```
make install
```

Or run Wine directly from the build directory:

```
./wine notepad
```

Run programs as `wine program`. For more information and problem
resolution, read the rest of this file, the Wine man page, and
especially the wealth of information found at https://www.winehq.org.


## REQUIREMENTS

To compile and run Wine, you must have one of the following:

- Linux version 2.6.22 or later
- FreeBSD 12.4 or later
- Solaris x86 9 or later
- NetBSD-current
- Mac OS X 10.12 or later

As Wine requires kernel-level thread support to run, only the operating
systems mentioned above are supported.  Other operating systems which
support kernel threads may be supported in the future.

**FreeBSD info**:
  See https://wiki.freebsd.org/Wine for more information.

**Solaris info**:
  You will most likely need to build Wine with the GNU toolchain
  (gcc, gas, etc.). Warning : installing gas does *not* ensure that it
  will be used by gcc. Recompiling gcc after installing gas or
  symlinking cc, as and ld to the gnu tools is said to be necessary.

**NetBSD info**:
  Make sure you have the USER_LDT, SYSVSHM, SYSVSEM, and SYSVMSG options
  turned on in your kernel.

**Mac OS X info**:
  You need Xcode/Xcode Command Line Tools or Apple cctools.  The
  minimum requirements for compiling Wine are clang 3.8 with the
  MacOSX10.10.sdk and mingw-w64 v8.  The MacOSX10.14.sdk and later can
  only build wine64.

**Supported file systems**:
  Wine should run on most file systems. A few compatibility problems
  have also been reported using files accessed through Samba. Also,
  NTFS does not provide all the file system features needed by some
  applications.  Using a native Unix file system is recommended.

**Basic requirements**:
  You need to have the X11 development include files installed
  (called xorg-dev in Debian and libX11-devel in Red Hat).
  Of course you also need make (most likely GNU make).
  You also need flex version 2.5.33 or later and bison.

**Optional support libraries**:
  Configure will display notices when optional libraries are not found
  on your system. See https://gitlab.winehq.org/wine/wine/-/wikis/Building-Wine
  for hints about the packages you should install. On 64-bit
  platforms, you have to make sure to install the 32-bit versions of
  these libraries.


## COMPILATION

To build Wine, do:

```
./configure
make
```

This will build the program "wine" and numerous support libraries/binaries.
The program "wine" will load and run Windows executables.
The library "libwine" ("Winelib") can be used to compile and link
Windows source code under Unix.

To see compile configuration options, do `./configure --help`.

For more information, see https://gitlab.winehq.org/wine/wine/-/wikis/Building-Wine


## SETUP

Once Wine has been built correctly, you can do `make install`; this
will install the wine executable and libraries, the Wine man page, and
other needed files.

Don't forget to uninstall any conflicting previous Wine installation
first.  Try either `dpkg -r wine` or `rpm -e wine` or `make uninstall`
before installing.

Once installed, you can run the `winecfg` configuration tool. See the
Support area at https://www.winehq.org/ for configuration hints.


## RUNNING PROGRAMS

When invoking Wine, you may specify the entire path to the executable,
or a filename only.

For example, to run Notepad:

```
wine notepad            (using the search Path as specified in
wine notepad.exe         the registry to locate the file)

wine c:\\windows\\notepad.exe      (using DOS filename syntax)

wine ~/.wine/drive_c/windows/notepad.exe  (using Unix filename syntax)

wine notepad.exe readme.txt          (calling program with parameters)
```

Wine is not perfect, so some programs may crash. If that happens you
will get a crash log that you should attach to your report when filing
a bug.


## GETTING MORE INFORMATION

- **WWW**: A great deal of information about Wine is available from WineHQ at
	https://www.winehq.org/ : various Wine Guides, application database,
	bug tracking. This is probably the best starting point.

- **FAQ**: The Wine FAQ is located at https://gitlab.winehq.org/wine/wine/-/wikis/FAQ

- **Wiki**: The Wine Wiki is located at https://gitlab.winehq.org/wine/wine/-/wikis/

- **Gitlab**: Wine development is hosted at https://gitlab.winehq.org

- **Mailing lists**:
	There are several mailing lists for Wine users and developers; see
	https://gitlab.winehq.org/wine/wine/-/wikis/Forums for more
	information.

- **Bugs**: Report bugs to Wine Bugzilla at https://bugs.winehq.org
	Please search the bugzilla database to check whether your
	problem is already known or fixed before posting a bug report.

- **IRC**: Online help is available at channel `#WineHQ` on irc.libera.chat.
