# Melammu Wine Patch Policy + Ledger (swingby-wine)

Last updated: 2026-07-05

This repository is the canonical Wine fork for Melammu. The git base is the
**vanilla WineHQ Wine 10.0 release** (`b0738596` "Release 10.0.", Alexandre
Julliard); all macOS/Rosetta work is carried by this fork's own patches
(56 commits / 93 files changed over the base, `b0738596..HEAD`, Verified at: 2026-07-05 / `git rev-list --count b0738596..HEAD` + `git diff --shortstat b0738596..HEAD`).
Sikarugir (formerly Kegworks) is historical lineage
and credit only — measured source delta over WineHQ 10.0 in this repo is zero
(no Sikarugir commits are carried here). WineHQ is the upstream to rebase onto.
Melammu runtime behavior must not depend on untracked binaries copied from
third-party wrappers.

---

# Patch Ledger（索引 / 請求書）

**目的**: 修正着手のたびに過去ログを漁るのをやめる。「d3d9 で過去に何を触ったか」「SE 崩れを何で直したか」を**この索引から即引ける**。かつ **自前発明 vs 本家 backport の境界**を明示する。下の Policy 以降（責任分界・Patch Classes・Build Artifact Rule）は方針書として保持。ここは請求書。

## 使い方 / 再生成

- **骨格は git から半自動生成**（症状・根因は手で注釈）:
  - コミット骨格: `git log --date=short --pretty='%h|%ad|%s' b0738596..HEAD`
  - 差分規模: `git diff --stat b0738596..HEAD`
  - 自前マーカー分布: `git grep -nE 'swingby|SWINGBY|melammu|MELAMMU|orrery|wukiyo' -- 'dlls/**' 'server/**' 'include/**'`
  - **rebuild 時はこの3コマンドを再走**し、行が増減していないか差分検知する（drift 検知）。
- **md5 は重複させない**: load-bearing バイナリの md5・配備先・source commit は [`Melammu/docs/reproducibility-ledger.md`](../Melammu/docs/reproducibility-ledger.md) が正典。ここは「台帳 #N」で指すだけ。
- **fidelity タグ**: ✅ = git/実機で確定（hard）。🟡 = load-bearing だがコード実読で確定していない（soft）。🟡要確認 = ②/③ 境界がコード実読を要する。

## 3段（provenance）の定義

パッチの**出自**を3段で分ける（下の Patch Classes = core/gated/experimental は直交する「配備ステータス」軸で、別列）。

- **① 素の Wine 10.0** — 触っていない（base 以降なので定義上ゼロ件）。
- **② upstream backport / 借用** — 10.0 以降の本家 fix の cherry-pick、または第三者 patch の rebase。汎用 Wine 改善の性格。
- **③ 自前発明** — swingby/melammu マーカー付き、または macOS/Rosetta/CMVS/Melammu 固有の独自実装。**「自分が当てた内容」はこの段を見れば一望できる**。

**全56コミットが単一 author（fork owner）**＝author では段を判別できない。分類は commit message 語彙（Backport/Original-author/底本）＋マーカー導入有無＋パッチ内容に依拠（✅ git 由来 / 🟡 境界はコード実読要）。件数は再生成コマンドで確認し、2026-07-05 時点は **② 11 / ③ 33 / D(doc・chore・merge) 12**。

## ③ 自前発明（＝自分が当てた内容の一望）

論理パッチ単位（反復コミットは範囲に畳んだ）。file:function は代表箇所。

| # | commit(s) / date | file:function | 症状 / 目的 | engine/game | 根因ポインタ | md5(台帳#) | class |
|---|---|---|---|---|---|---|---|
| 1 | `d053267`(05-26)〜`15b45c6`(06-14, ~20 commits) | `dlls/d3d9/surface.c` / `device.c` / `swapchain.c` / `d3d9_main.c` ＋ `dlls/wined3d/swapchain.c`（＋vendored `stb_image_write.h`） | CMVS セーブ画面サムネが黒。back-buffer READONLY lock で last-presented frame を serve、UnlockRect counter で 192x108 検出→injection。`surface.c:swingby_patch_dat_file_impl` には CMVS `.dat` 直接書換え能力も残る（gate 内・破壊的能力なので反応的に剥がさず ledger 対象） | CMVS | `research/state/thumbnail.md`、`journeys/2026-06-28-hamidashi-thumbnail-gl-readback-black-rootcause.md` | 台帳外（bundled wine builtin d3d9） | Engine Gated `MELAMMU_CMVS_THUMBS` 🟡潜在的に脆い（正解は launcher SCK single-writer＝thumbnail.md 参照。per-game d3d9 経路は反応的に剥がさない） |
| 2 | `dad6d47`(05-13) | `dlls/winemac.drv/image.c: macdrv_GetImage` | GDI BitBlt が Metal 描画窓で黒を返す→CGWindowList で窓内容を捕捉 | winemac 全般 | `research/state/thumbnail.md` | 台帳外（bundled winemac） | Core Required |
| 3 | `0491875`(06-13) | `dlls/wow64cpu/cpu.c` | 32bit ゲームが Rosetta で c0000005。far-call を ljmp→lretq に thunk | 全32bit game | `journeys/2026-06-13-wine-prot-exec-map-file-into-view-fix.md`（関連） | 台帳外（bundled wow64cpu） | Core Required ✅ |
| 4 | `b585585`(06-13) | `dlls/ntdll/loader.c` | delay-load IAT を patch 前に PAGE_READWRITE 化（mingw binutils≥2.43 ld bug 32675 回避） | macOS toolchain | — | 台帳外（bundled ntdll） | Core Required ✅ |
| 5 | `e9a93b3`(06-12) | `dlls/ntdll/unix/virtual.c` | macOS AMFI が PROT_EXEC mmap を拒否→PROT なし mmap→mprotect で exec 付与 | 全 game | `journeys/2026-06-13-wine-prot-exec-map-file-into-view-fix.md` | 台帳外（bundled ntdll） | Core Required 🟡要確認（Sikarugir out-of-tree から concept port＝②寄りの境界） |
| 6 | `e96197a`(06-12) | `dlls/win32u/window.c` | NtUserSetWindowLong の self-referencing subclass で stack overflow | yaneurao GameSDK | — | 台帳外（bundled win32u） | Core Required |
| 7 | `d294887`(06-13), `d1fa6f3`+`3b6256b`(06-23), `b4a6cfb`(06-25), `8d4919b`(06-30) | `dlls/winemac.drv/{opengl.c,window.c,cocoa_window.m}` | GL-over-Metal overlay（DXVK/MoltenVK 窓上に D3D9/GL を present）／画面外窓の中央復帰／OnMainThread 再入 deadlock／movie「白」時の overlay un-hide | winemac（DXVK 描画・movie） | `research/state/movie.md`、`journeys/2026-06-30-hamidashi-movie-white-dxvk-metal-wined3d-overlay-journey.md` | #3, #4（winemac.drv PE / winemac.so） | Core Required（`b4a6cfb` は 🟡要確認＝汎用 deadlock fix） |
| 8 | `0aba0f6`(06-29) | `dlls/dsound/mixer.c: swingby_clamp_float_mix` | in-game SE/BGM の float mix クリップノイズを [-1,1] に saturate | title gated（Hamidashi） | `research/state/audio.md` | #8（Hamidashi dsound） | Engine/Title Gated |
| 9 | `bee6762`(06-29) | `dlls/dsound/primary.c` | app 要求 primary rate が device より高い時にデバイス再オープン（SRC を CoreAudio へ offload） | title gated（Hamidashi） | `research/state/audio.md` | #8 | Engine/Title Gated |
| 10 | `5aed1fc`(07-04) | `dlls/imagehlp/integrity.c: ImageGetDigestStream` | SoftDenchi `UCOpgDlg.dll` 自己署名検証を通す per-section PE digest（c0000142 解消） | SoftDenchi DRM | メモリ [[softdenchi-blocked-by-wine-imagehlp-authenticode-mismatch]] | #16, #17 | 旧 Experimental→現 shared 🟡要確認（汎用 Wine correctness としても筋が通る） |
| 11a | `8d4919b`(06-30, master) | `dlls/ddraw/surface.c` + `dlls/winemac.drv/*` | ddraw/VMR-7 front-buffer movie を DXVK/Metal 上に表示（overlay un-hide + surface early-ready）。共有 ddraw/winemac 側の movie 白 fix | Furukiss/GIGA・Hamidashi movie | `research/state/movie.md`, `journeys/2026-06-30-hamidashi-movie-white-dxvk-metal-wined3d-overlay-journey.md` | #3,#4,#6a,#6b,#13-15 | Core Required / title overlay source |
| 11b | `1ae2460`(topic: `origin/quartz-dsound-startup-avsync` / `verify/hamidashi-quartz-logo-avsync`) | `dlls/quartz/filtergraph.c` / `dsoundrender.c` | Hamidashi startup logo route（`MELAMMU_LOGO_*` env-gated Null Renderer / 200ms delay skip）＋ movie pre-roll `cur < 0` 連続扱い。shared master ではなく title-local `quartz.dll` artifact の source | Hamidashi logo | `research/state/movie.md`, `Melammu/docs/reproducibility-ledger.md` #11 | #11 | Title Gated / topic branch source |

## ② upstream backport / 借用

汎用 Wine fix の性格。macOS 固有マーカーをほぼ持たない。

| # | commit(s) / date | file:function | 内容 | 根因ポインタ | md5(台帳#) | 段判定 |
|---|---|---|---|---|---|---|
| B1 | `baf3e94`(06-30) | `dlls/ntdll/unix/msync.{c,h}` ＋ `server/msync.{c,h}` ＋ `server/*` | msync(mach semaphore)。**底本 marzent/wine-msync (LGPL2.1)** を Wine10.0 へ rebase。in-process 同期＝movie「白」(~5.16s) 解消 | メモリ [[nukitashi-movie-white-is-startup-latency]]、`research/state/movie.md` | #1, #2 | ②（借用ベース・macOS 適合は自前）🟡 |
| B2 | `6bbb4f4`(06-25) | `dlls/mf/topology_loader.c` | 動画変換で color converter を既定に。**明示 backport** upstream `774bbd4153c` / Original-author Rémi Bernon (CodeWeavers) | — | — | ② ✅（明示 backport） |
| B3 | `5fc3eac`(06-25) | `dlls/winegstreamer/{color_convert,video_processor}.c` | MFT output type を補完し EVR mixer に通す | `journeys/2026-06-27-hamidashi-op-audio-starvation-winegstreamer-multiqueue-journey.md` | — | ② 🟡要確認 |
| B4 | `61dc20e`+`29cfa3b`(06-22), `aa872c7`+`6f32d23`(06-23) | `dlls/quartz/{vmr7,vmr9,vmr7_presenter,filtergraph}.c` ＋tests | VMR7/9 image presenter 実装・present rect・graph lock 回避（EOS deadlock）・RGB24 対応 | `journeys/2026-06-23-...evr-white-thumbnail-black-journey.md`、`journeys/2026-06-25-galsfiction-...-evr-black-journey.md` | #9-#11 | ② 🟡要確認（汎用 quartz 実装・test 付） |
| B5 | `3b4d01e`(06-24) | `dlls/ddraw/surface.c` | 空 clip list 時の unclipped windowed primary blt（Furukiss/GIGA VMR7 OP 黒対策） | `journeys/2026-06-24-furukiss-s-giga-op-movie-black-journey.md` | #6a, #6b | ② 🟡要確認 |
| B6 | `cb07279`(06-23) | `dlls/dxva2/main.c` | video processor render target を実 RT で作成（macOS GL FBO 起因） | — | — | ② 🟡要確認 |

## D — doc / chore / merge（コード非改変・12件）

索引の対象外（README/PATCHES 編集・`wukiyo→swingby` リネーム `bf97c45`・gitignore・merge `e4cea6c`）。機能不変。必要時は `git log --grep` で辿る。

## 要確認リスト（コード実読で②/③境界を確定すべき）

以下は commit message とマーカーだけでは段が確定せず、コード diff の実読が要る。**load-bearing になる前に実物で昇格**（メモリ [[feedback-fidelity-tag-and-load-bearing-promotion]]・全部は verify しない）:

1. `baf3e94` msync — 借用(marzent LGPL2.1)ベース＋macOS 適合の自前調整。②か「借用ベースの自前」か。差分最大(~3,500行)。
2. `e9a93b3` PROT_EXEC — Sikarugir から "concept, not verbatim" port。②(backport)か③(再実装)か移植度次第。
3. `5fc3eac`/`b4a6cfb`/`3b4d01e`/`6f32d23`/`cb07279`/`aa872c7`/`61dc20e`/`29cfa3b` — quartz/winegstreamer/ddraw/dxva2 の 8件。汎用 Wine fix の性格だが upstream 由来の明記なし＋macOS 面が絡む。「upstream-shaped な自前実装」か「未 push の backport 候補」か。
4. `5aed1fc` imagehlp — 汎用 Wine 正当性向上だが動機は SoftDenchi。②/③ どちらでも筋が通る。
5. `stb_image_write.h` — 第三者 public-domain lib の vendoring。①②③ でなく「vendored dependency」の第4カテゴリが要るか。

---

## Responsibility Boundary

`swingby-wine` owns:

- Wine behavior patches.
- Patch gates and default-off behavior.
- Regression surface and compatibility notes for each patch class.
- Reproducible build inputs for artifacts shipped by Melammu.

`Melammu` owns:

- Prefix lifecycle and game data lifecycle.
- Engine detection and per-engine policy.
- Runtime selection, `WINEPREFIX`, `WINEDLLPATH`, GStreamer, DXVK, and DLL
  override policy.
- Per-title feature flags.
- The bundled runtime manifest under `docs/wine-runtime-manifest.md`.

## Canonical Branch Policy

Target policy:

- Public default / canonical branch: `master` (Wine fork convention; no `main` branch).
- `master` contains Melammu's supported Wine patch set.
- Phase 0 authority is the runtime content currently used by the Melammu
  launcher, not an existing branch name or version string.
- v1 `master` is the minimal clean fork needed to reproduce the current Melammu
  bundle (no Wine version upgrade; stays on the WineHQ 10.0 base).
- Experimental game-specific probes live on topic branches and are not bundled
  until promoted by a manifest update.
- Launcher state, agent state, local research notes, and build directories do
  not belong in public history.

Current Phase 0 source candidate:

```text
e6310c904ca5ddc9d8a78017057ba9f661c2f57a
feat(d3d9,wined3d): MELAMMU_CMVS_THUMBS ...
```

This commit is a candidate source explanation for the current Melammu bundle,
but the bundle is authoritative until a clean rebuild proves equivalence by
feature probes and hashes.

v1 `master` includes:

- Core patches required by the current Melammu bundle.
- `MELAMMU_CMVS_THUMBS` as a default-off engine gate.

v1 `master` excludes:

- SoftDenchi WTS / crypt32 work.
- Wine version upgrades.
- `wine64/` integration into this fork (wine64 stays a separate
  launcher-bundled compatibility runtime under `wine-support/wine64/`).
- Title policy, fallback policy, and launcher policy.

SoftDenchi-related work after that point is experimental/post-v1 and must not
be included in the canonical v1 runtime without a separate gate:

```text
930fe5b75a5... wtsapi32 WTS session nudge (`verify/softdenchi-wts-session`)
635d5380509... crypt32 CryptBinaryToStringA(CRYPT_STRING_HEX) (`verify/softdenchi-wts-session`)
```

## Patch Classes

### Core Required

These patches are part of the supported Melammu Wine runtime and should be
carried by the canonical branch.

- `dlls/wow64cpu/cpu.c`: Rosetta-aware far-call thunking for 32-bit games.
- `dlls/ntdll/loader.c`: make delay-load IAT writable before patching.
- `dlls/ntdll/unix/virtual.c`: avoid initial executable file mappings on
  macOS, then apply executable protection explicitly.
- `dlls/win32u/window.c`: guard self-referencing window subclass updates.
- `dlls/winemac.drv/*`: macOS window behavior and capture support used by
  Melammu.

### Engine Gated

These patches must be default-off inside Wine and enabled by Melammu only for
the engine/title policy that requires them.

- CMVS thumbnail capture and last-presented back-buffer serving.
- Gate: `MELAMMU_CMVS_THUMBS`.
- IPC contract: `/tmp/melammu_snap_NNN.bgra` with
  `[u32 width][u32 height][u32 stride] + BGRA pixels`, plus
  `/tmp/melammu_page_base.txt`.

### Experimental / Post-v1

These patches are not part of the v1 canonical runtime until explicitly
promoted.

- `dlls/wtsapi32/wtsapi32.c`: WTS session nudge for SoftDenchi experiments.
- `dlls/crypt32/base64.c`: `CryptBinaryToStringA(CRYPT_STRING_HEX)` work until
  promoted as a generic Wine compatibility fix.

## Build Artifact Rule

The shipped Melammu runtime must be tied back to source by content, not by
mtime. Before publishing or rebasing:

1. Build from the intended canonical commit.
2. Bundle into Melammu.
3. Record the commit, feature probes, and SHA-256 hashes in Melammu's
   `docs/wine-runtime-manifest.md`.
4. Verify that experimental patches are absent unless the manifest explicitly
   says otherwise.
