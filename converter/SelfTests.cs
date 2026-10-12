// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;

internal static class SelfTests
{
    private static void Check(bool condition, string name)
    {
        if (!condition) throw new Exception("Self-test failed: " + name);
    }

    public static void Run()
    {
        Result r = Program.ConvertRules("||ads.example.com^\nEXACT.example.net\n||ads.example.com^\n");
        Check(r.Entries.SetEquals(new[] { "ads.example.com", "*.ads.example.com", "exact.example.net" }), "suffix, exact, deduplication");
        r = Program.ConvertRules("||parent.example.com^\n||ads.parent.example.com^\n@@||good.parent.example.com^\n");
        Check(!r.Entries.Contains("parent.example.com") && r.Entries.Contains("ads.parent.example.com"), "exception hole removes broad parent, retains disjoint child");
        r = Program.ConvertRules("||ads.example.com^\n@@||example.com^\n");
        Check(r.Entries.Count == 0, "parent exception suppresses child");
        r = Program.ConvertRules("||exponea.com^\n||cdn.us1.exponea.com^\n@@||cdn.us*.exponea.com^|\n");
        Check(r.Entries.Count == 0, "wildcard exception conservatively broadens");
        r = Program.ConvertRules("||metric.gstatic.com^\n@@-ds.metric.gstatic.com^|\n");
        Check(r.Entries.Count == 0, "unanchored exception suffix");
        r = Program.ConvertRules("||ads.example.com^\n||ads.example.com^$badfilter\n");
        Check(r.Entries.Count == 0 && r.Disabled == 1, "badfilter disables original");
        r = Program.ConvertRules("||ads.example.com^$dnstype=A\n||ads*.example.net^\n/^ads/\n||safe.example.org^$important\n");
        Check(r.Entries.Count == 2 && r.Skipped.Count == 3, "conditional and regex block rules cannot widen");
        r = Program.ConvertRules("||ads.example.com^\n@@||ads.example.com^$dnstype=A\n");
        Check(r.Entries.Count == 0, "conditional exception conservatively broadens");
        r = Program.ConvertRules("||ads.example.com^\n" + @"@@/\.(gif|jpe?g|png|webp)#(\/?.+)?(\/(ad)s?\/|\/ad-)/" + "\n");
        Check(r.Entries.Count == 2, "URL-only exception cannot match DNS");
        bool rejected = false;
        try { Program.ConvertRules("||ads.example.com^\n@@/^ads/\n"); }
        catch (InvalidDataException) { rejected = true; }
        Check(rejected, "unknown exception rejects entire conversion");
        r = Program.ConvertRules("||ads.example.com^$important\n||ads.example.com^$badfilter,important\n");
        Check(r.Entries.Count == 0 && r.Disabled == 1, "badfilter with other modifiers");
        r = Program.ConvertRules("||evilfoo.example.com^\n@@||*foo.example.com^\n");
        Check(r.Entries.Count == 0, "partial label wildcard exception");
        r = Program.ConvertRules("||evilfoo.example.com^\n@@foo.example.com^|\n");
        Check(r.Entries.Count == 0, "unanchored partial label exception");
        rejected = false;
        try { Program.ConvertRules(@"@@/(ads\.example\.com|#)/"); }
        catch (InvalidDataException) { rejected = true; }
        Check(rejected, "regex alternative with hash must not be ignored");
        Console.WriteLine("Self-tests passed (14 cases).");
    }
}
