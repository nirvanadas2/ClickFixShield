using ClickFixShield.Core.Contracts;
using ClickFixShield.Core.Models;

namespace ClickFixShield.App;

/// <summary>Lists recent <see cref="SecurityEvent"/>s from the event store; double-click opens full detail.</summary>
public sealed class EventHistoryForm : Form
{
    private readonly IEventStore _eventStore;
    private readonly ListView _listView;

    public EventHistoryForm(IEventStore eventStore)
    {
        _eventStore = eventStore;

        Text = "ClickFixShield - Recent Events";
        ClientSize = new Size(720, 420);
        StartPosition = FormStartPosition.CenterScreen;

        _listView = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            MultiSelect = false
        };
        _listView.Columns.Add("Timestamp", 150);
        _listView.Columns.Add("Source", 90);
        _listView.Columns.Add("Severity", 80);
        _listView.Columns.Add("Score", 50);
        _listView.Columns.Add("Action", 120);
        _listView.Columns.Add("Summary", 200);
        _listView.DoubleClick += OnItemDoubleClick;

        Controls.Add(_listView);

        Load += (_, _) => RefreshEvents();
    }

    private void RefreshEvents()
    {
        _listView.Items.Clear();

        foreach (var evt in _eventStore.GetRecent(200))
        {
            var item = new ListViewItem(evt.Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"))
            {
                Tag = evt,
                ForeColor = SeverityColor(evt.Detection.Level)
            };
            item.SubItems.Add(evt.Source.ToString());
            item.SubItems.Add(evt.Detection.Level.ToString());
            item.SubItems.Add(evt.Detection.Score.ToString());
            item.SubItems.Add(evt.ActionTaken.ToString());
            item.SubItems.Add(Truncate(evt.RawText, 60));

            _listView.Items.Add(item);
        }
    }

    private void OnItemDoubleClick(object? sender, EventArgs e)
    {
        if (_listView.SelectedItems.Count == 0)
        {
            return;
        }

        if (_listView.SelectedItems[0].Tag is SecurityEvent evt)
        {
            new ThreatDetailForm(evt).Show();
        }
    }

    private static string Truncate(string text, int maxLength)
        => text.Length <= maxLength ? text : text[..maxLength] + "...";

    private static Color SeverityColor(ThreatLevel level) => level switch
    {
        ThreatLevel.Safe => Color.Black,
        ThreatLevel.Suspicious => Color.DarkGoldenrod,
        ThreatLevel.HighRisk => Color.OrangeRed,
        ThreatLevel.Malicious => Color.Red,
        _ => Color.Black
    };
}
