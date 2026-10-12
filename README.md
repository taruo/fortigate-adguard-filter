# AdGuard DNS filter for FortiGate

[日本語](README.md) | [English](README.en.md)

公式の **AdGuard DNS filter** を FortiGate の Domain Name 外部フィード用に変換して配信します。
DNS の問い合わせ経路に追加のサーバーを配置する必要はありません。

配信するのは **遮断対象だけを含む1本のリスト** `fortigate-domains.txt` です。
AdGuard の許可例外は変換時に処理し、例外に重なる遮断ルールを配信前に取り除きます。
FortiGate は取得したリストを **Block** として使用します。

## FortiGate に登録する URL

```text
https://raw.githubusercontent.com/taruo/fortigate-adguard-filter/main/fortigate-domains.txt
```

以下は、FortiGate を端末の DNS サーバーとして使う構成の手順です。
端末がその DNS サーバーへ送信する問い合わせがフィルターの対象になります。
メニュー名や利用条件は、使用するバージョン・構成に合わせて確認してください。

1. **Security Fabric → External Connectors → Create New → Domain Name** を開く。
2. Name を `AdGuard-DNS`、Update method を `External Feed` にする。
3. URL に上記の Raw URL を登録。Refresh Rate は `1440` 分（1日）を目安にする。
4. 証明書検証は `full` にする。接続後に **View Entries** で内容を確認する。
5. DNS Filter プロファイルの **FortiGuard Category Based Filter** を有効にし、**Remote Categories** に表示される `AdGuard-DNS` を **Block** にする（GUI では **Redirect to Block Portal** と表示される場合があります）。
6. **Network → DNS Servers → DNS Service on Interface** で、端末が利用するインターフェースの DNS サービスを開く。メニューがない場合は **System → Feature Visibility → DNS Database** を有効にする。
7. DNS サービスの Mode を **Recursive** にし、DNS Filter に上記のプロファイルを指定する。
8. DHCP または端末の DNS 設定で、このインターフェースの IP アドレスを DNS サーバーに指定する。

外部ドメインフィードの判定と、FortiGuard のオンラインカテゴリ判定は区別して設定してください。
オンラインカテゴリ判定が失敗したときも通常の名前解決を継続する構成では、プロファイルの **Allow DNS requests when a rating error occurs** を有効にします。これは判定エラー時の通過を許可する設定です。
適用後は、対象の DNS サーバーを明示して、リスト内ドメインの遮断と、通常ドメインの名前解決を確認してください。
デフォルトの遮断動作はブロックポータルへのリダイレクトです。DNS 応答が返るだけでは許可されたとは判断できないため、DNS ログのカテゴリと Action も確認してください。

変換器は100万件・32 MBを上限として検証します。
機器の取り込み上限はモデルと FortiOS に依存するため、他のドメインフィードも含めた合計件数を[公式仕様](https://docs.fortinet.com/document/fortigate/7.4.11/administration-guide/9463/threat-feeds)と照合してください。

## 更新と障害時の動作

- GitHub Actions が毎日 **06:17 JST** に取得・変換・検証する。実行時刻は混雑等で遅れる場合があります。
- Actions の **Update FortiGate filter → Run workflow** で手動更新も可能。
- ダウンロード失敗、未対応の許可例外、10万件未満、100万件超、32 MB超では公開しない。
- 前回から10%を超えて減少、または25%を超えて増加した場合も公開を止め、既存ファイルを維持する。
- GitHub 停止時は FortiGate の取得済みフィードで判定を継続し、更新だけが止まる。
- 公開リポジトリの標準 GitHub ランナーで動作し、Actions の実行は無料。
- 公開リポジトリに60日間活動がないと定期実行が無効になる場合があります。Actions 画面で再有効化できます。

## 変換の範囲

AdGuard の全機能を再現する変換ではなく、誤遮断を避ける保守的な変換です。

- `||example.com^` → `example.com` と `*.example.com`。
- ドメインだけの行、完全一致の行は完全一致として出力。
- `$badfilter` は元ルールを無効にする。`$important` の優先度は再現せず、変換時に許可例外と競合する遮断を除く。
- 許可例外は出力リストから遮断対象を除くことで反映する。ワイルドカード・条件付きの許可例外は除外範囲を広く解釈する。
- 親ドメインの遮断が許可された子ドメインを巻き込む場合、親の遮断ルール全体を除く。
- 正規表現・ワイルドカード・条件付きの遮断ルール等、正確に変換できないルールは除外して報告。
- DNS名に一致しない URL 用の許可例外を除き、解釈できない許可例外は更新全体を失敗させる。

結果として、元の AdGuard より遮断範囲が狭くなる場合があります。
詳細は [変換報告](reports/conversion.txt)、元の入力は [ソーススナップショット](sources/adguard-dns.txt) を参照。

## 親子関係による主な制約

この単一リストは遮断対象だけを含みます。親をまとめて遮断しながら特定の子だけを通す穴は、変換時に親の広い遮断を除くことで処理します。
以下の「遮断対象から外れる」は、このリストによる遮断がなくなるという意味です。他のセキュリティ設定による遮断まで解除するものではありません。

### 1. 子の例外により、親と他の兄弟の遮断も外れる

元ルール:

```text
||example.com^
@@||good.example.com^
||ads.example.com^
```

出力に残る遮断エントリー:

```text
*.ads.example.com
ads.example.com
```

例外を巻き込む `example.com` と `*.example.com` の遮断を取り除くため、影響は `good.example.com` だけに限定されません。

| ドメイン | この例での変換後の扱い |
| --- | --- |
| `good.example.com` とその子孫 | 例外により遮断対象から外れる |
| `example.com` 本体 | 親の遮断を除くため、遮断対象から外れる |
| `other.example.com` | 兄弟を含む広い遮断がなくなり、遮断対象から外れる |
| `ads.example.com` とその子孫 | 例外と重ならない個別の遮断が残る |

新しく現れた兄弟ドメインも、個別の遮断ルールがなければ、このリストでは遮断されません。

### 2. 親の許可例外は、子の個別遮断も除く

元ルール:

```text
@@||example.com^
||ads.example.com^
```

この例では遮断エントリーは残りません。
`ads.example.com` は親の例外範囲に含まれるため、個別の遮断ルールがあっても取り除きます。
例1で子の遮断が残るのは、その子が例外の範囲と重ならない場合だけです。

### 3. 完全一致の許可例外も、子孫まで広げて除外する

元ルール:

```text
||good.example.com^
||ads.good.example.com^
@@|good.example.com^|
```

完全一致形式の例外も、この変換では `good.example.com` とその子孫の除外として扱います。
そのため、`good.example.com` だけでなく `ads.good.example.com` の遮断も取り除き、この例では遮断エントリーは残りません。
「本体だけを通して、その子孫は遮断する」という元ルールの境界を厳密には再現しません。

### 4. ワイルドカード例外では、除外範囲が親全体まで広がる場合がある

元ルール:

```text
||example.com^
||ads.example.com^
@@||cdn*.example.com^
```

この例外は、変換時にワイルドカードの後ろの固定部分 `example.com` を基準に、親とその子孫全体の除外へ広げます。
その結果、`cdn1.example.com` などだけでなく、`ads.example.com` の個別遮断も取り除き、この例では遮断エントリーは残りません。
誤遮断を避けるため、元の AdGuard の例外より広い範囲で遮断を外す場合があります。

## ローカルでの実行

.NET 8 SDK があれば、追加ライブラリや秘密情報は不要です。

```text
dotnet run --project converter -- --self-test
dotnet run --project converter -- source-filter.txt .
```

件数変化が意図したものと確認できた場合のみ、最後に `--allow-large-change` を付けて手動変換できます。
このオプションでも絶対件数・サイズ上限と許可例外の検証は省略しません。
更新時は出力・ソース・変換報告の3つをまとめてコミットしてください。

## 出典・ライセンス

AdGuard DNS filter は **AdGuard Software Ltd / AdguardTeam と各元フィルターの貢献者**によるものです。
このリポジトリは非公式の変換・配信プロジェクトで、AdGuard および Fortinet の公式製品ではありません。

- [公式ソース](https://github.com/AdguardTeam/AdGuardSDNSFilter)
- [入力URL](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt)
- [AdGuard DNSルールの仕様](https://adguard-dns.io/kb/general/dns-filtering-syntax/)
- [FortiOS 7.4.11 外部フィードの仕様](https://docs.fortinet.com/document/fortigate/7.4.11/administration-guide/9463/threat-feeds)
- [FortiGate DNS サーバーへの DNS Filter 適用](https://docs.fortinet.com/document/fortigate/7.4.9/administration-guide/121810/applying-dns-filter-to-fortigate-dns-server)
- [GitHub Actions の料金](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
- [定期実行の条件](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)

配布フィルターおよび変換コードは **GPL-3.0-or-later**。原文は [LICENSE](LICENSE)。
元リストの著作権・出典コメントは `sources/adguard-dns.txt` 内にそのまま保持します。
