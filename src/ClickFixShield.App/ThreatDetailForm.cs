using ClickFixShield.Core.Models;

namespace ClickFixShield.App;

/// <summary>Shows the full detail of a single <see cref="SecurityEvent"/>.</summary>
public sealed class ThreatDetailForm : Form
{
    public ThreatDetailForm(SecurityEvent evt)
    {
        Text = "ClickFixShield - Threat Detail";
        ClientSize = new Size(520, 420);
        StartPosition = FormStartPosition.CenterScreen;
        MinimizeBox = false;
        MaximizeBox = false;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var matchedRules = evt.Detection.MatchedRuleIds.Count == 0
            ? "(none)"
            : string.Join(", ", evt.Detection.MatchedRuleIds);

        var summary = new Label
        {
            AutoSize = true,
            Padding = new Padding(10),
            Text =
                $"Timestamp: {evt.Timestamp.ToLocalTime():yyyy-MM-dd HH:mm:ss}\n" +
                $"Source: {evt.Source}\n" +
                $"Action taken: {evt.ActionTaken}\n" +
                $"Severity: {evt.Detection.Level} (score {evt.Detection.Score})\n" +
                $"Matched rules: {matchedRules}\n" +
                $"Explanation: {evt.Detection.Explanation ?? "(none)"}"
        };

        var rawLabel = new Label
        {
            AutoSize = true,
            Padding = new Padding(10, 0, 10, 0),
            Text = "Raw text:"
        };

        var rawTextBox = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            WordWrap = true,
            ScrollBars = ScrollBars.Vertical,
            Margin = new Padding(10),
            Text = evt.RawText
        };

        root.Controls.Add(summary, 0, 0);
        root.Controls.Add(rawLabel, 0, 1);
        root.Controls.Add(rawTextBox, 0, 2);

        Controls.Add(root);
    }
}
