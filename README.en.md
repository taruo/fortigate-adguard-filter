# AdGuard DNS filter for FortiGate

[日本語](README.md) | [English](README.en.md)

This project converts the official **AdGuard DNS filter** into a FortiGate Domain Name external feed and publishes the result on GitHub.
It does not require an additional server in the DNS query path.

The published output is **one list containing only domains to block**, `fortigate-domains.txt`.
AdGuard exceptions are handled during conversion: conflicting block rules are removed before publication.
FortiGate uses the downloaded list with the **Block** action.

## Feed URL

```text
https://raw.githubusercontent.com/taruo/fortigate-adguard-filter/main/fortigate-domains.txt
```

The following procedure uses FortiGate as the clients' DNS server.
Queries sent by clients to that DNS server are subject to the filter.
Check menu names and feature requirements for your version and configuration.

1. Open **Security Fabric → External Connectors → Create New → Domain Name**.
2. Set the name to `AdGuard-DNS` and the update method to `External Feed`.
3. Enter the Raw URL above. A refresh rate of `1440` minutes (one day) is a reasonable starting point.
4. Set server certificate validation to `full`. After connecting, check **View Entries**.
5. In your DNS Filter profile, enable **FortiGuard Category Based Filter**, and set `AdGuard-DNS` under **Remote Categories** to **Block** (the GUI may label this **Redirect to Block Portal**).
6. Open the DNS service for the interface used by clients under **Network → DNS Servers → DNS Service on Interface**. If the menu is hidden, enable **System → Feature Visibility → DNS Database**.
7. Set the DNS service mode to **Recursive**, and select the profile above under DNS Filter.
8. Configure DHCP or each client's DNS settings to use that interface's IP address as the DNS server.

Configure external domain feed filtering separately from FortiGuard online category lookups.
To keep ordinary DNS resolution working when online category lookups fail, enable **Allow DNS requests when a rating error occurs** in the profile. This setting permits queries when a rating error occurs.
After applying the profile, explicitly query that DNS server to verify that a listed domain is blocked and an ordinary domain still resolves.
The default blocking behavior redirects to the block portal. Receiving a DNS answer alone does not establish that a query was allowed; check the category and action in the DNS logs as well.

The converter enforces limits of one million entries and 32 MB.
Device import limits depend on the model and FortiOS version. Include other domain feeds in the total and check the [official specification](https://docs.fortinet.com/document/fortigate/7.4.11/administration-guide/9463/threat-feeds).

## Updates and failure behavior

- GitHub Actions downloads, converts, and validates the source every day at **21:17 UTC / 06:17 JST**. Scheduled runs may be delayed.
- You can also update manually through **Actions → Update FortiGate filter → Run workflow**.
- Publishing stops if the download fails, an unsupported exception is encountered, the output has fewer than 100,000 or more than 1,000,000 entries, or the file exceeds 32 MB.
- A decrease of more than 10% or an increase of more than 25% from the previous entry count also stops publication and preserves the existing files.
- If GitHub becomes unreachable, FortiGate continues using the feed it has already downloaded; only updates stop.
- The workflow uses standard GitHub-hosted runners in a public repository, for which GitHub Actions execution is free.
- Scheduled workflows in public repositories can be disabled after 60 days without repository activity. They can be re-enabled on the Actions page.

## Conversion scope

This is a conservative conversion designed to avoid unintended blocking. It does not reproduce every AdGuard feature.

- `||example.com^` becomes `example.com` and `*.example.com`.
- Domain-only and exact-hostname rules produce exact matches.
- `$badfilter` disables the corresponding rule. `$important` precedence is not reproduced; blocks that conflict with exceptions are removed during conversion.
- Exceptions are applied by removing blocked domains from the output. Wildcard and conditional exceptions are interpreted broadly when determining which blocks to remove.
- If blocking a parent domain would also block an allowed child domain, the entire parent-domain block is removed.
- Blocking rules that cannot be converted accurately, including regex, wildcard, and conditional blocking rules, are skipped and reported.
- Except for a specifically recognized URL-only exception that cannot match DNS hostnames, an unrecognized exception fails the entire update.

The converted feed may therefore block fewer domains than the original AdGuard filter.
See the [conversion report](reports/conversion.txt) for details and the [source snapshot](sources/adguard-dns.txt) for the input used.

## Parent and child domain limitations

This single list contains only domains to block. To accommodate an exception for a child within a broad parent block, the converter removes the broad parent block before publication.
In the examples below, "removed from blocking" means that this list no longer blocks the domain. It does not override blocks imposed by other security settings.

### 1. A child exception also removes the broad block for its parent and siblings

Source rules:

```text
||example.com^
@@||good.example.com^
||ads.example.com^
```

Remaining block entries:

```text
*.ads.example.com
ads.example.com
```

The `example.com` and `*.example.com` blocks are removed because they would include the exception. The effect extends beyond `good.example.com`.

| Domain | Result of conversion in this example |
| --- | --- |
| `good.example.com` and its descendants | Removed from blocking because of the exception |
| `example.com` itself | Removed from blocking along with the broad parent rule |
| `other.example.com` | Removed from blocking because the broad rule covering siblings is gone |
| `ads.example.com` and its descendants | Remain blocked by the separate rule that does not overlap the exception |

New sibling domains are also not blocked by this list unless they have a separate blocking rule.

### 2. A parent exception also removes separate child blocks

Source rules:

```text
@@||example.com^
||ads.example.com^
```

No block entries remain in this example.
The separate `ads.example.com` block is removed because that domain falls within the parent exception.
The child block in example 1 survives only because it does not overlap the exception's scope.

### 3. An exact-hostname exception is broadened to include descendants

Source rules:

```text
||good.example.com^
||ads.good.example.com^
@@|good.example.com^|
```

The converter treats even this exact-hostname exception as an exclusion for `good.example.com` and all its descendants.
Both `good.example.com` and `ads.good.example.com` are therefore removed from blocking, leaving no block entries in this example.
The source rule's distinction between allowing only the hostname itself and blocking its descendants is not preserved exactly.

### 4. A wildcard exception can broaden the exclusion to the entire parent domain

Source rules:

```text
||example.com^
||ads.example.com^
@@||cdn*.example.com^
```

The converter uses the fixed suffix after the wildcard, `example.com`, to broaden this exception to the parent and all its descendants.
As a result, the separate `ads.example.com` block is also removed, rather than excluding only names such as `cdn1.example.com`. No block entries remain in this example.
To avoid unintended blocking, conversion can exclude a broader scope than the original AdGuard exception.

## Local execution

The converter requires the .NET 8 SDK. No additional libraries or secrets are needed.

```text
dotnet run --project converter -- --self-test
dotnet run --project converter -- source-filter.txt .
```

Only after reviewing and confirming an intentional entry-count change, append `--allow-large-change` to the conversion command.
This option does not bypass absolute count limits, file size limits, or exception validation.
Commit the generated feed, source snapshot, and conversion report together.

## Attribution and license

The AdGuard DNS filter is maintained by **AdGuard Software Ltd / AdguardTeam and contributors to its source filter lists**.
This is an unofficial conversion and distribution project, not an official AdGuard or Fortinet product.

- [Official source](https://github.com/AdguardTeam/AdGuardSDNSFilter)
- [Input URL](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt)
- [AdGuard DNS filtering syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/)
- [FortiOS 7.4.11 external feed specification](https://docs.fortinet.com/document/fortigate/7.4.11/administration-guide/9463/threat-feeds)
- [Applying DNS Filter to the FortiGate DNS server](https://docs.fortinet.com/document/fortigate/7.4.9/administration-guide/121810/applying-dns-filter-to-fortigate-dns-server)
- [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
- [Scheduled workflow conditions](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)

The distributed filter and conversion code are licensed under **GPL-3.0-or-later**; see [LICENSE](LICENSE).
Original copyright notices and source comments are preserved in `sources/adguard-dns.txt`.
