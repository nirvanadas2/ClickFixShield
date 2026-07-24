namespace ClickFixShield.Core.Interception;

/// <summary>Configurable knobs for <see cref="RunInterceptionDecider"/> / <see cref="ProcessInterceptor"/>.</summary>
public sealed class ProcessInterceptorOptions
{
    /// <summary>
    /// Living-off-the-land binaries eligible for a Kill decision. A process is NEVER
    /// killed unless its (path-stripped, case-insensitive) name is in this list -
    /// severity alone is never sufficient.
    /// </summary>
    public static readonly IReadOnlyList<string> DefaultLolBinAllowlist = new[]
    {
        "powershell.exe",
        "powershell_ise.exe",
        "pwsh.exe",
        "cmd.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe",
        "certutil.exe",
        "curl.exe",
        "bitsadmin.exe",
        "rundll32.exe",
        "regsvr32.exe"
    };

    public IReadOnlyList<string> LolBinAllowlist { get; init; } = DefaultLolBinAllowlist;

    /// <summary>How recent a clipboard correlation match must be to enrich the decision explanation.</summary>
    public TimeSpan CorrelationTtl { get; init; } = TimeSpan.FromSeconds(20);
}
