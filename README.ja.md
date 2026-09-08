# Swingby Wine（`swingby-wine`）

[English](README.md)

> **ARM64移行用の実験ブランチです。** `master`は既存のRosetta依存系統を維持します。
> このブランチはWine 11.12系とARM64 CPU変換を統合する開発候補であり、そのまま
> インストールできる完成版ではありません。[CPU依存の入力](runtime/arm64/README.md)を
> 同梱していますが、runtime全体の再現可能なビルド手順は整備中です。

**Swingby Wine**（repository: `swingby-wine`）は、Orreryの非公開ランチャー本体**Melammu**で利用する、
Apple Silicon Mac向けの公開Wine forkです。Windows向けビジュアルノベルをゲーム本体の
実行ファイルやデータを書き換えず、Macアプリとして扱うための互換処理を実装しています。

[WineHQ Wine 10.0](https://gitlab.winehq.org/wine/wine)のrelease
`b0738596`から始まる履歴を継承し、この移行ブランチでは新しい基盤を統合しています。
正確な基盤は[SWINGBY_PATCHES.md](SWINGBY_PATCHES.md)を参照してください。macOS向けのWine-side patchをこのrepoで
管理します。runtime選択、bundle、署名、release policyは非公開Melammuの責任であり、
ランチャー本体や配布用artifactはここに含みません。

このforkはmacOS Wineの先行事例として
[Sikarugir](https://github.com/Sikarugir-App/Sikarugir)をcreditしています。
実行memory処理の一部は、出典を明記した概念移植・非逐語再実装であり、Sikarugirの
sourceをそのまま取り込んだものではありません。詳細な境界は
[SWINGBY_PATCHES.md](SWINGBY_PATCHES.md)へ記録しています。

## このリポジトリで確認できること

| 領域 | 主な実装・設計 |
|---|---|
| Apple Siliconでの32bit実行 | `wow64cpu`のRosetta対応、`ntdll`の実行memory処理 |
| macOS固有の表示・window処理 | `winemac.drv`、`win32u`、DirectDraw、WineD3Dの互換対応 |
| 動画・音声経路 | Quartz、WineGStreamer、DXVA2、DirectSound、CoreAudio周辺の互換対応 |
| engine / title固有処理の隔離 | `MELAMMU_CMVS_THUMBS`などを明示的なgateで既定OFFにする設計 |
| patchの出自管理 | WineHQ backport、出典ありの概念移植、独自変更を分ける台帳 |

動作確認の射程は、実際に検証した作品・version・起動経路・runtimeに限定します。
このrepoはWineのsourceとbuild手順を公開するもので、Melammuの完成appではありません。

## Orreryにおける位置づけ

| 対象 | 役割 |
|---|---|
| **Melammu** | Orreryで実際に開発・利用する非公開のmacOSランチャー本体 |
| **Swingby Wine** | Melammuが利用する公開Wine source fork |
| **[Swingby DXVK](https://github.com/tsukasa-art/swingby-dxvk)** | Melammuが利用する公開DXVK source fork（MoltenVK/Apple Silicon互換性修正） |
| **[melammu-vn](https://github.com/tsukasa-art/melammu-vn)** | SwiftUI UIと汎用判定を切り出したsource-only公開参照実装。完成ランチャー、runtime同梱版、release配布物ではない |

## 公開ブランチ

正典の統合枝は`master`だけです。それ以外の公開branchは、検証可能な実験履歴または
復旧用履歴を保存するrefであり、別系統のruntime bundleではありません。

| ブランチ | 目的 | 現在の扱い |
|---|---|---|
| `master` | WineHQ Wine 10.0 releaseをbaseとする、Melammu向けの保守対象patch set | **正典。** 保守する変更はここへ統合します。Wine forkの慣例に合わせて`main`ではなく`master`を使用します。 |
| `quartz-dsound-startup-avsync` | DirectSoundのstartup preroll、WineGStreamerのqueue、build provenance、関連diagnosticsを検証したmedia/audio実験 | **複合実験履歴。** 採用済みの着想、置換済みthumbnail実験、未解決WIPが混在します。branch全体をmerge・bundleせず、必要なcommitを個別に評価します。 |
| `quartz-vmr9-image-presenter` | movie presentation経路を調査した歴史的milestone | **`master`へ包含済み。** branch名は当初のVMR9仮説を残していますが、検証後の修正経路はVMR7 presenterのrectangle、window retarget、graph lock処理でした。現役の開発枝ではありません。 |
| `backup/pre-purge-master-fa93c4d-2026-06-15` | rehabilitation前の`master` snapshot | **復旧参照専用。** このbranchでは開発しません。 |

Verified at: 2026-07-22（`git ls-remote --heads origin`と`origin/master`に対する
ancestry確認）。

## 現行graphics runtimeの境界

非公開Melammuは、作品・engineごとの検証結果に基づいてrendererを選びます。

- **WineD3D / OpenGL**は、多くのD3D9・DirectDraw経路の基準です。
- **DXVK -> Vulkan -> MoltenVK -> Metal**は、検証済みの経路で選択します。
  WineD3Dを一律に置き換える構成ではありません。
- D3D9 / DirectDrawをWineD3Dに残し、D3D11だけDXVKへ分けるmixed routeもあります。
  renderer選択は非公開ランチャー、Wine側patchと既定OFF gateはこのrepoの責任です。

Apple D3DMetal / Game Porting Toolkit componentは、ここで説明する現行runtime構成には
含めません。

## Build（macOS / Rosetta 2）

Xcode Command Line Toolsとx86_64 Homebrew（`/usr/local/bin/brew`）を使用します。

```bash
mkdir build && cd build
arch -x86_64 env \
  PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/share/pkgconfig \
  LDFLAGS="-L/usr/local/lib" CPPFLAGS="-I/usr/local/include" \
  ../configure -C --enable-win64 --with-mingw \
  BISON=/usr/local/opt/bison/bin/bison
arch -x86_64 make -s -j$(sysctl -n hw.activecpu)
```

build結果はWine artifactであり、Melammuの完成appではありません。private Melammuのscript、
bundle内path、title別配備手順は公開読者向け手順にしません。統合側ではPE/Unix moduleの
ABI整合、source revisionとhashの記録、署名・配布条件の確認が別途必要です。

## 関連リンク

- [Orrery — プロジェクト概要](https://tsukasa-art.com/projects/orrery/)
- [Orrery Case Notes](https://tsukasa-art.com/projects/orrery/#research-notes-title) — privateな運用情報を除いた公開互換調査
- [Swingby DXVK — 公開DXVK fork](https://github.com/tsukasa-art/swingby-dxvk)
- [melammu-vn — source-only公開参照実装](https://github.com/tsukasa-art/melammu-vn)
- [Zenn連載 第1回](https://zenn.dev/tsukasa_art/articles/mac-eroge-compat-part1) — 連載の入口。現行runtime状態の証拠ではない
- [Zenn: WukiyoをOrreryへ再編した](https://zenn.dev/tsukasa_art/articles/melammu-wukiyo-bridge) — プロジェクト再編と連載の地図。現行runtime状態の証拠ではない
- [Sikarugir](https://github.com/Sikarugir-App/Sikarugir) — macOS Wine開発の先行事例

## License

WineとこのforkはGNU LGPLの条件に従います。詳細は[LICENSE](LICENSE)と
[COPYING.LIB](COPYING.LIB)を参照してください。
