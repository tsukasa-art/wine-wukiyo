# Melammu Wine Patch Policy + Ledger (swingby-wine)

Last updated: 2026-09-07

This repository is the public Wine fork used by the private Melammu launcher.
The existing stable lineage starts at **WineHQ Wine 10.0** (`b0738596`,
"Release 10.0.", Alexandre Julliard). The `arm64-wine-11.12` branch integrates
WineHQ `0c1585cf5bb9a29a5c480ee04d5529b8fc236044`, 15 commits after the official
11.12 release, while retaining that Swingby lineage. It is an experimental
migration candidate, not a replacement for the accepted runtime on `master`.
Moving commit and file counts are not used as product capability claims.

[Sikarugir](https://github.com/Sikarugir-App/Sikarugir) is credited as macOS
Wine prior art, but its Wine tree is not carried wholesale. Patch `e9a93b3` is
an attributed conceptual port and non-verbatim reimplementation of two
Sikarugir executable-memory changes. It is classified separately from original
fork inventions below.

The current [CodeWeavers source page](https://www.codeweavers.com/crossover/source)
is included as general FOSS credit only. It does not directly substantiate a
historical CrossOver-release-specific capability decision, and this public
ledger does not use it as evidence for one.

The public [melammu-vn](https://github.com/tsukasa-art/melammu-vn) repository is
a source-only reference implementation. It is not the complete launcher and
does not contain Melammu's runtime selection, title profiles, private evidence,
or release artifacts.

---

# Patch Ledger

This ledger separates source provenance from deployment status. Commit hashes
identify public source history; they are not fixed-size project claims.

## Reading the ledger

- **Provenance** describes where an implementation came from.
- **Class** describes whether the patch is shared, gated, or experimental.
- **Related Case Note** points to public technical background. It is not a claim
  that the Case Note directly proves every implementation detail in that row.
- Private launcher paths, deployment scripts, operational records, and artifact
  manifests are intentionally not linked here.

## Provenance categories

- **① WineHQ Wine 10.0 base** — unchanged upstream source.
- **② Upstream backport / borrowed base** — later WineHQ fixes or attributed
  third-party work rebased onto Wine 10.0.
- **②-B Attributed conceptual port** — source-attributed ideas reimplemented
  non-verbatim for this fork.
- **③ Original fork change** — implementation developed in this fork without
  claiming third-party source authorship.

Authorship alone does not establish provenance. Classification follows commit
messages, source attribution, and direct code review.

## ③ Original fork changes

| # | commit(s) | representative area | purpose | related Case Note | class |
|---|---|---|---|---|---|
| 1 | `d053267`–`15b45c6`; hardening `b6aff9ef219` + `6432d63fc76` | `dlls/d3d9/*`, `dlls/wined3d/swapchain.c` | Keep last-presented-frame and snapshot injection behind a default-off gate | [save thumbnail](https://tsukasa-art.com/projects/orrery/notes/save-thumbnail-black/) | Engine Gated: `MELAMMU_CMVS_THUMBS` |
| 2 | `dad6d47`; cleanup `b6aff9ef219` | `dlls/winemac.drv/image.c` | Improve GDI capture behavior for a macOS-rendered window and remove debug-only writes | [save thumbnail](https://tsukasa-art.com/projects/orrery/notes/save-thumbnail-black/) | Core Required |
| 3 | `0491875` | `dlls/wow64cpu/cpu.c` | Replace a Rosetta-sensitive 32-bit far-call path with a compatible thunk | [executable-memory background](https://tsukasa-art.com/projects/orrery/notes/mmap-exec-launch-crash/) | Core Required |
| 4 | `b585585` | `dlls/ntdll/loader.c` | Make delay-load IAT pages writable before patching | — | Core Required |
| 6 | `e96197a` | `dlls/win32u/window.c` | Guard self-referencing window subclass updates | — | Core Required |
| 7 | `d294887`, `d1fa6f3` + `3b6256b`, `b4a6cfb`, `8d4919b` | `dlls/winemac.drv/*` | Coordinate DXVK/MoltenVK drawing with WineD3D/DirectDraw movie presentation | [movie white screen](https://tsukasa-art.com/projects/orrery/notes/movie-white-screen/) | Core Required; some boundaries remain under review |
| 8 | `0aba0f6` | `dlls/dsound/mixer.c` | Saturate float mixing to the valid range | — | Engine / Title Gated |
| 9 | `bee6762` | `dlls/dsound/primary.c` | Leave sample-rate conversion to CoreAudio for a gated route | — | Engine / Title Gated |
| 10 | `5aed1fc` | `dlls/imagehlp/integrity.c` | Improve per-section PE digest compatibility | — | Shared; provenance classification remains under review |
| 11a | `8d4919b` | `dlls/ddraw/surface.c`, `dlls/winemac.drv/*` | Present a VMR-7 front-buffer movie through a mixed graphics window | [movie white screen](https://tsukasa-art.com/projects/orrery/notes/movie-white-screen/) | Core Required |
| 11b | `1ae2460` | `dlls/quartz/filtergraph.c`, `dsoundrender.c` | Gate startup-logo and movie pre-roll behavior | [first-load lifecycle](https://tsukasa-art.com/projects/orrery/notes/movie-first-load-after-app-update/) | Title Gated |
| 12 | `6c217e5` | `dlls/winecoreaudio.drv/coreaudio.c` | Prefer the system-default endpoint with stock enumeration as fallback | — | Shared |
| 13 | `1471f547fba` | `dlls/ddraw/surface.c` | Intersect an out-of-bounds destination and proportionally crop the source | — | High-risk shared change; limited to verified routes |

## ②-B Attributed conceptual port / non-verbatim reimplementation

| # | commit | representative area | source boundary | related Case Note | class |
|---|---|---|---|---|---|
| 5 | `e9a93b3` | `dlls/ntdll/unix/virtual.c` | Conceptually follows Sikarugir executable-memory work, but reimplements the behavior non-verbatim on the WineHQ 10.0 base | [mmap / executable memory](https://tsukasa-art.com/projects/orrery/notes/mmap-exec-launch-crash/) | Core Required |

## ② Upstream backports / borrowed bases

| # | commit(s) | representative area | source boundary | related Case Note | class |
|---|---|---|---|---|---|
| B1 | `baf3e94` | `dlls/ntdll/unix/msync.*`, `server/msync.*` | `marzent/wine-msync` LGPL-2.1 base rebased onto Wine 10.0, with macOS adaptation maintained here | — | Borrowed base; adaptation boundary remains under review |
| B2 | `6bbb4f4` | `dlls/mf/topology_loader.c` | Explicit WineHQ backport of `774bbd4153c`; original author Rémi Bernon (CodeWeavers) | — | Upstream backport |
| B3 | `5fc3eac` | `dlls/winegstreamer/{color_convert,video_processor}.c` | Upstream-shaped media-foundation compatibility work; exact provenance remains under review | [movie / audio starvation](https://tsukasa-art.com/projects/orrery/notes/movie-audio-starvation/) | Under review |
| B4 | `61dc20e` + `29cfa3b`, `aa872c7` + `6f32d23` | `dlls/quartz/*` | VMR7/9 presenter, rectangle, graph-lock, and RGB24 work | [movie white screen](https://tsukasa-art.com/projects/orrery/notes/movie-white-screen/) | Under review |
| B5 | `3b4d01e` | `dlls/ddraw/surface.c` | Windowed-primary blit behavior for an empty clip list | [movie white screen](https://tsukasa-art.com/projects/orrery/notes/movie-white-screen/) | Under review |
| B6 | `cb07279` | `dlls/dxva2/main.c` | Create the video-processor render target from the actual target resource | — | Under review |
| B7 | `8ca998d09e4` | `dlls/user32/{user32.spec,win.c}` | Backport the `IsWindowArranged` stub from WineHQ `a7d7024479e` | [Electron launcher](https://tsukasa-art.com/projects/orrery/notes/electron-windows-launcher-on-wine/) | WineHQ backport |

## Items still requiring provenance review

- `baf3e94`: borrowed msync base versus fork-specific macOS adaptation.
- Media and DirectDraw group: whether each change is an unpublished backport or
  an independently implemented upstream-shaped fix.
- `5aed1fc`: generic Wine correctness versus application-driven motivation.
- `stb_image_write.h`: vendored public-domain dependency, outside the three
  implementation categories above.

---

## Responsibility boundary

`swingby-wine` owns:

- Wine behavior patches.
- Patch gates and default-off behavior.
- Regression surfaces and compatibility notes for each patch class.
- Reproducible Wine-side build inputs.

The private `Melammu` project owns:

- Prefix and game-data lifecycle.
- Engine detection and per-engine policy.
- Runtime selection, GStreamer, DXVK, MoltenVK, and DLL override policy.
- Per-title feature flags, artifact hashes, signing, deployment, and rollback.

The public `melammu-vn` repository owns none of those runtime responsibilities.
It is a source-only reference implementation for a curated SwiftUI library UI
and generic engine detection.

## Current OSS runtime composition

The graphics model is selected per engine and title; it is not one global
renderer:

- **WineD3D / OpenGL** is the baseline for many D3D9 and DirectDraw routes.
- **DXVK -> Vulkan -> MoltenVK -> Metal** is used for verified D3D11 and
  selected D3D9 routes. Some routes must keep D3D9 on WineD3D.
- **Mixed routing** is intentional: D3D9 or DirectDraw can remain builtin while
  D3D11 uses DXVK. WineGStreamer / GStreamer, Quartz, DirectSound, and CoreAudio
  cover the media and audio sides of the runtime.

Apple D3DMetal / Game Porting Toolkit components are not part of the current
runtime described by this ledger.

## Canonical branch policy

- Public default and canonical branch: `master` (Wine fork convention; no
  `main` branch).
- `master` contains the public Wine-side source set accepted for integration.
- Experimental game-specific probes remain on topic branches until promoted by
  an explicit source decision.
- Launcher state, private operational records, and build directories do not
  belong in public history.

## Patch classes

### Core Required

Shared Wine behavior required by supported routes, including the Rosetta-aware
32-bit path, delay-load protection, executable-memory handling, window subclass
guard, and macOS window behavior.

### Engine / Title Gated

Compatibility behavior that must remain default-off and be enabled only by an
explicit launcher policy. `MELAMMU_CMVS_THUMBS` is the public example of this
boundary.

### Experimental / Post-v1

Unpromoted probes are not part of the canonical runtime until they pass a
separate source, artifact, and regression decision.

## Build artifact rule

Runtime artifacts must be tied back to source by content, not timestamps:

1. Build from the intended public source commit.
2. Keep PE and Unix-side modules ABI-matched.
3. Record source revision, feature probes, and hashes in the integrating
   project's private records.
4. Verify that experimental patches are absent unless explicitly selected.

These are maintainer gates, not public instructions for assembling the private
Melammu launcher.

## Credits and license

- WineHQ Wine 10.0 is the upstream base and is licensed under the GNU LGPL.
- Sikarugir is credited for macOS Wine prior art and the concept behind patch
  `e9a93b3`; its source is not copied verbatim.
- `marzent/wine-msync` is credited as the LGPL-2.1 base for B1.
- WineHQ and original authors, including CodeWeavers contributors, retain their
  attribution on backported commits.
- See [LICENSE](LICENSE) and [COPYING.LIB](COPYING.LIB).

## Public navigation

- [Orrery overview](https://tsukasa-art.com/projects/orrery/)
- [Orrery Case Notes](https://tsukasa-art.com/projects/orrery/#research-notes-title)
- [melammu-vn source-only reference](https://github.com/tsukasa-art/melammu-vn)
- [Zenn series, part 1](https://zenn.dev/tsukasa_art/articles/mac-eroge-compat-part1) — entry point to the series, not evidence of the current runtime state
- [Zenn: Wukiyo to Melammu](https://zenn.dev/tsukasa_art/articles/melammu-wukiyo-bridge) — naming transition and series map, not evidence of the current runtime state

## ARM64 migration integration

The migration branch carries the tested XTAJIT32/64 and Unicorn connection,
ARM64EC memory and exception handling, and limited 32-bit Unix-call bridges.
The earlier Wine10 msync integration is replaced as a unit with the modern
in-process synchronization integration used by this candidate. Original source
copyright and license notices remain in the imported files.

Existing compatibility changes are carried forward by behavior:

- The self-referencing subclass guard uses server-owned window-procedure state.
- RGB24 VMR-7 conversion is retained alongside upstream BI_BITFIELDS support.
- Media output dimensions and uncompressed-sample attributes move to the
  `colorcnv` and `msvproc` modules; deleted WineGStreamer implementations are
  not restored.
- Float mix saturation remains on the shared float mixer path.
- The existing macOS capture exports and GL overlay helpers are retained with
  the refactored OpenGL driver and client-view representation.
- The x86 Rosetta thunk remains for that separate architecture; ARM64 CPU
  translation uses XTAJIT instead.

The old `build.sh` remains the x86 build route. ARM64 validation uses a separate
build directory, a matching multi-architecture llvm-mingw toolchain, and the
selected Unicorn library. Limited CPU and drawing checks do not establish
full media, mixed GL/Metal, title-specific capture, or product-runtime parity.
