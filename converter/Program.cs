// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

internal sealed class Result
{
    public readonly SortedSet<string> Entries = new SortedSet<string>(StringComparer.Ordinal);
    public readonly List<string> Skipped = new List<string>();
    public readonly List<string> Exceptions = new List<string>();
    public int Suppressed;
    public int Disabled;
}

internal static class Program
{
    public const string SourceUrl = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt";
    private static readonly Regex Domain = new Regex(
        @"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$",
        RegexOptions.CultureInvariant);

    private static string Normalize(string domain)
    {
        domain = domain.ToLowerInvariant();
        if (!Domain.IsMatch(domain)) return null;
        return domain;
    }

    private static IEnumerable<string> Suffixes(string domain)
    {
        while (true)
        {
            yield return domain;
            int dot = domain.IndexOf('.');
            if (dot < 0) yield break;
            domain = domain.Substring(dot + 1);
        }
    }

    private static string CanonicalRule(string rule, out bool badfilter)
    {
        badfilter = false;
        int dollar = rule.IndexOf('$');
        if (dollar < 0) return rule;
        var modifiers = rule.Substring(dollar + 1).Split(',').ToList();
        badfilter = modifiers.Remove("badfilter");
        modifiers.Sort(StringComparer.Ordinal);
        return rule.Substring(0, dollar) + (modifiers.Count == 0 ? "" : "$" + string.Join(",", modifiers));
    }

    public static Result ConvertRules(string text)
    {
        var result = new Result();
        var lines = text.Replace("\r", "").Split('\n').Select(x => x.Trim()).ToArray();
        var disabled = new HashSet<string>(StringComparer.Ordinal);
        foreach (string line in lines)
        {
            if (line.StartsWith("!") || line.StartsWith("#")) continue;
            bool badfilter;
            string canonical = CanonicalRule(line, out badfilter);
            if (badfilter) disabled.Add(canonical);
        }
        var allowed = new HashSet<string>(StringComparer.Ordinal);
        var blocked = new Dictionary<string, bool>(StringComparer.Ordinal);
        foreach (string original in lines)
        {
            if (original.Length == 0 || original.StartsWith("!") || original.StartsWith("#") ||
                original == "[Adblock Plus 2.0]") continue;
            bool badfilter;
            string canonical = CanonicalRule(original, out badfilter);
            if (badfilter) continue;
            if (disabled.Contains(canonical)) { result.Disabled++; continue; }
            bool exception = original.StartsWith("@@", StringComparison.Ordinal);
            string rule = exception ? original.Substring(2) : original;
            int dollar = rule.IndexOf('$');
            if (dollar >= 0)
            {
                string modifiers = rule.Substring(dollar + 1);
                rule = rule.Substring(0, dollar);
                // Conditional block rules cannot safely become unconditional blocks.
                if (!exception && modifiers != "important")
                {
                    result.Skipped.Add("Unsupported block modifier: " + original);
                    continue;
                }
                // Broaden conditional exceptions, preferring missed ads to broken sites.
            }
            if (exception)
            {
                // Only this exact upstream URL exception is known to require a literal '#'.
                // Arbitrary regex containing '#' could still match DNS via an alternative.
                if (rule == @"/\.(gif|jpe?g|png|webp)#(\/?.+)?(\/(ad)s?\/|\/ad-)/")
                {
                    result.Skipped.Add("Exception cannot match a DNS hostname: " + original);
                    continue;
                }
                if (rule.StartsWith("/"))
                    throw new InvalidDataException("Cannot safely convert regex exception: " + original);
                string mask = rule;
                bool unanchored = !mask.StartsWith("|");
                if (!mask.EndsWith("^", StringComparison.Ordinal) && !mask.EndsWith("^|", StringComparison.Ordinal))
                    throw new InvalidDataException("Cannot safely convert exception anchors: " + original);
                if (mask.StartsWith("||")) mask = mask.Substring(2);
                else if (mask.StartsWith("|")) mask = mask.Substring(1);
                if (mask.EndsWith("|")) mask = mask.Substring(0, mask.Length - 1);
                if (mask.EndsWith("^")) mask = mask.Substring(0, mask.Length - 1);
                // Wildcard exceptions: allow the fixed suffix after the last wildcard.
                int star = mask.LastIndexOf('*');
                if (star >= 0)
                {
                    mask = mask.Substring(star + 1);
                    // A wildcard before a partial label also permits evilfoo.example.com.
                    if (!mask.StartsWith(".")) unanchored = true;
                    mask = mask.TrimStart('.');
                }
                // Unanchored/partial-label suffix: allow its next full-label parent.
                if (unanchored)
                {
                    int dot = mask.IndexOf('.');
                    mask = dot < 0 ? "" : mask.Substring(dot + 1);
                }
                string allow = Normalize(mask);
                if (allow == null)
                    throw new InvalidDataException("Cannot safely convert exception: " + original);
                allowed.Add(allow);
                result.Exceptions.Add(original + " => allow " + allow + " and subdomains");
                continue;
            }
            bool subdomains = false;
            string name = null;
            if (rule.StartsWith("||") && rule.EndsWith("^"))
            {
                name = Normalize(rule.Substring(2, rule.Length - 3));
                subdomains = true;
            }
            else if (rule.StartsWith("|") && !rule.StartsWith("||") && rule.EndsWith("^|"))
                name = Normalize(rule.Substring(1, rule.Length - 3));
            else
                name = Normalize(rule); // Domain-only syntax: exact hostname only.
            if (name == null)
            {
                result.Skipped.Add("Unsupported block pattern: " + original);
                continue;
            }
            bool existing;
            blocked[name] = subdomains || (blocked.TryGetValue(name, out existing) && existing);
        }
        var allowAncestors = new HashSet<string>(StringComparer.Ordinal);
        foreach (string allow in allowed)
            foreach (string suffix in Suffixes(allow)) allowAncestors.Add(suffix);
        foreach (var block in blocked)
        {
            bool overlaps = Suffixes(block.Key).Any(x => allowed.Contains(x));
            // A parent-domain wildcard cannot retain a hole for an allowed child.
            // Remove the whole parent block instead of accidentally blocking the child.
            if (block.Value && allowAncestors.Contains(block.Key)) overlaps = true;
            if (overlaps) { result.Suppressed++; continue; }
            result.Entries.Add(block.Key);
            if (block.Value) result.Entries.Add("*." + block.Key);
        }
        return result;
    }

    private static void AtomicWrite(string path, string content)
    {
        string temporary = path + ".tmp";
        File.WriteAllText(temporary, content, new UTF8Encoding(false));
        File.Move(temporary, path, true);
    }

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 1 && args[0] == "--self-test")
            {
                SelfTests.Run();
                return 0;
            }
            if (args.Length < 2 || args.Length > 3 ||
                (args.Length == 3 && args[2] != "--allow-large-change"))
                throw new ArgumentException("Usage: Converter INPUT_FILE OUTPUT_DIRECTORY [--allow-large-change]");
            string source = File.ReadAllText(args[0], Encoding.UTF8);
            if (!source.Contains("! Title: AdGuard DNS filter"))
                throw new InvalidDataException("The input is not the expected AdGuard DNS filter.");
            Result result = ConvertRules(source);
            if (result.Entries.Count < 100000 || result.Entries.Count > 1000000)
                throw new InvalidDataException("Unexpected entry count: " + result.Entries.Count);
            string root = Path.GetFullPath(args[1]);
            string target = Path.Combine(root, "fortigate-domains.txt");
            if (File.Exists(target) && args.Length != 3)
            {
                int previous = File.ReadLines(target).Count(x => x.Length > 0 && !x.StartsWith("#"));
                if (result.Entries.Count < previous * 0.90 || result.Entries.Count > previous * 1.25)
                    throw new InvalidDataException("Large count change; keeping the last published list. Review and use --allow-large-change if intentional.");
            }
            string digest;
            using (SHA256 sha = SHA256.Create())
                digest = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(source))).Replace("-", "").ToLowerInvariant();
            string content = "# AdGuard DNS filter converted for FortiGate\n# Source: " + SourceUrl +
                "\n# License: GPL-3.0-or-later; see LICENSE and sources/adguard-dns.txt\n# Source SHA256: " +
                digest + "\n# Conservative conversion; see reports/conversion.txt\n" +
                string.Join("\n", result.Entries) + "\n";
            if (Encoding.UTF8.GetByteCount(content) > 32 * 1024 * 1024)
                throw new InvalidDataException("Feed exceeds the 32 MB limit.");
            var report = new StringBuilder();
            report.AppendLine("Source SHA256: " + digest);
            report.AppendLine("Entries: " + result.Entries.Count);
            report.AppendLine("Suppressed blocks overlapping exceptions: " + result.Suppressed);
            report.AppendLine("Disabled by badfilter: " + result.Disabled);
            report.AppendLine("Skipped rules: " + result.Skipped.Count);
            report.AppendLine("\nException handling (conservative):");
            foreach (string line in result.Exceptions) report.AppendLine(line);
            report.AppendLine("\nSkipped rules:");
            foreach (string line in result.Skipped) report.AppendLine(line);
            Directory.CreateDirectory(root);
            Directory.CreateDirectory(Path.Combine(root, "reports"));
            Directory.CreateDirectory(Path.Combine(root, "sources"));
            // All validation precedes writes. Workflow commits only after complete success.
            AtomicWrite(Path.Combine(root, "sources", "adguard-dns.txt"), source);
            AtomicWrite(Path.Combine(root, "reports", "conversion.txt"), report.ToString().Replace("\r\n", "\n"));
            AtomicWrite(target, content);
            Console.WriteLine("Converted {0} entries; suppressed {1}; skipped {2}; bytes {3}.",
                result.Entries.Count, result.Suppressed, result.Skipped.Count, Encoding.UTF8.GetByteCount(content));
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }
}
