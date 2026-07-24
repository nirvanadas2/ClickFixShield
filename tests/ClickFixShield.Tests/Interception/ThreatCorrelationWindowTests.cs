using ClickFixShield.Core.Interception;
using Xunit;

namespace ClickFixShield.Tests.Interception;

public class ThreatCorrelationWindowTests
{
    [Fact]
    public void IsRecentMatch_ExactTextWithinWindow_ReturnsTrue()
    {
        var window = new ThreatCorrelationWindow();
        window.Record("powershell -enc ABCDEF", DateTimeOffset.UtcNow);

        Assert.True(window.IsRecentMatch("powershell -enc ABCDEF", TimeSpan.FromSeconds(20)));
    }

    [Fact]
    public void IsRecentMatch_RecordedTextIsSubstringOfLongerCandidate_ReturnsTrue()
    {
        // Real command lines wrap the pasted payload in extra shell syntax, so exact-only
        // matching would be too strict.
        var window = new ThreatCorrelationWindow();
        window.Record("powershell -enc ABCDEF", DateTimeOffset.UtcNow);

        Assert.True(window.IsRecentMatch("cmd /c \"powershell -enc ABCDEF\" & exit", TimeSpan.FromSeconds(20)));
    }

    [Fact]
    public void IsRecentMatch_OutsideWindow_ReturnsFalse()
    {
        var window = new ThreatCorrelationWindow();
        window.Record("powershell -enc ABCDEF", DateTimeOffset.UtcNow.AddSeconds(-90));

        Assert.False(window.IsRecentMatch("powershell -enc ABCDEF", TimeSpan.FromSeconds(20)));
    }

    [Fact]
    public void IsRecentMatch_NothingRecorded_ReturnsFalse()
    {
        var window = new ThreatCorrelationWindow();

        Assert.False(window.IsRecentMatch("anything at all here", TimeSpan.FromSeconds(20)));
    }
}
