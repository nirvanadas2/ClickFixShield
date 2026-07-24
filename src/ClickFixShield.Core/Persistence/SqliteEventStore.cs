using System.Globalization;
using System.Text.Json;
using ClickFixShield.Core.Contracts;
using ClickFixShield.Core.Models;
using Microsoft.Data.Sqlite;

namespace ClickFixShield.Core.Persistence;

/// <summary>
/// SQLite-backed <see cref="IEventStore"/>. Chosen over a flat file specifically so
/// <see cref="GetByMinimumLevel"/> is a real indexed range query over the stored
/// <see cref="ThreatLevel"/> ordinal, not an in-memory linear scan.
/// </summary>
public sealed class SqliteEventStore : IEventStore
{
    private readonly string _connectionString;
    private readonly object _schemaLock = new();
    private bool _schemaReady;

    public SqliteEventStore(string? databasePath = null)
    {
        var path = databasePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ClickFixShield",
            "events.db");

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        _connectionString = new SqliteConnectionStringBuilder { DataSource = path }.ToString();
        EnsureSchema();
    }

    public void Save(SecurityEvent evt)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Events (Id, Timestamp, Source, RawText, Score, Level, MatchedRuleIds, Explanation, ActionTaken)
            VALUES ($id, $timestamp, $source, $rawText, $score, $level, $matchedRuleIds, $explanation, $actionTaken);
            """;
        command.Parameters.AddWithValue("$id", evt.Id.ToString());
        command.Parameters.AddWithValue("$timestamp", ToStorageString(evt.Timestamp));
        command.Parameters.AddWithValue("$source", (int)evt.Source);
        command.Parameters.AddWithValue("$rawText", evt.RawText);
        command.Parameters.AddWithValue("$score", evt.Detection.Score);
        command.Parameters.AddWithValue("$level", (int)evt.Detection.Level);
        command.Parameters.AddWithValue("$matchedRuleIds", JsonSerializer.Serialize(evt.Detection.MatchedRuleIds));
        command.Parameters.AddWithValue("$explanation", (object?)evt.Detection.Explanation ?? DBNull.Value);
        command.Parameters.AddWithValue("$actionTaken", (int)evt.ActionTaken);
        command.ExecuteNonQuery();
    }

    public IReadOnlyList<SecurityEvent> GetRecent(int count)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = $"{SelectColumns} FROM Events ORDER BY Timestamp DESC LIMIT $count;";
        command.Parameters.AddWithValue("$count", count);

        using var reader = command.ExecuteReader();
        var results = new List<SecurityEvent>();
        while (reader.Read())
        {
            results.Add(ReadEvent(reader));
        }

        return results;
    }

    public SecurityEvent? GetById(Guid id)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = $"{SelectColumns} FROM Events WHERE Id = $id LIMIT 1;";
        command.Parameters.AddWithValue("$id", id.ToString());

        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadEvent(reader) : null;
    }

    public IReadOnlyList<SecurityEvent> GetByMinimumLevel(ThreatLevel minLevel, int count)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        // Level is indexed (IX_Events_Level) - this is a real range scan, not a linear filter.
        command.CommandText = $"{SelectColumns} FROM Events WHERE Level >= $minLevel ORDER BY Timestamp DESC LIMIT $count;";
        command.Parameters.AddWithValue("$minLevel", (int)minLevel);
        command.Parameters.AddWithValue("$count", count);

        using var reader = command.ExecuteReader();
        var results = new List<SecurityEvent>();
        while (reader.Read())
        {
            results.Add(ReadEvent(reader));
        }

        return results;
    }

    private const string SelectColumns =
        "SELECT Id, Timestamp, Source, RawText, Score, Level, MatchedRuleIds, Explanation, ActionTaken";

    private static SecurityEvent ReadEvent(SqliteDataReader reader)
    {
        var id = Guid.Parse(reader.GetString(0));
        var timestamp = FromStorageString(reader.GetString(1));
        var source = (ThreatSource)reader.GetInt32(2);
        var rawText = reader.GetString(3);
        var score = reader.GetInt32(4);
        var level = (ThreatLevel)reader.GetInt32(5);
        var matchedRuleIds = JsonSerializer.Deserialize<List<string>>(reader.GetString(6)) ?? new List<string>();
        var explanation = reader.IsDBNull(7) ? null : reader.GetString(7);
        var actionTaken = (ThreatAction)reader.GetInt32(8);

        var detection = new DetectionResult(score, level, matchedRuleIds, explanation);
        return new SecurityEvent(id, timestamp, source, rawText, detection, actionTaken);
    }

    // Stored as the UTC instant in a fixed-width round-trip format so lexicographic TEXT
    // ordering (used by ORDER BY Timestamp) matches chronological ordering regardless of
    // the original DateTimeOffset's local offset.
    private static string ToStorageString(DateTimeOffset value)
        => value.UtcDateTime.ToString("o", CultureInfo.InvariantCulture);

    private static DateTimeOffset FromStorageString(string value)
        => new(DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind), TimeSpan.Zero);

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    private void EnsureSchema()
    {
        if (_schemaReady)
        {
            return;
        }

        lock (_schemaLock)
        {
            if (_schemaReady)
            {
                return;
            }

            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE IF NOT EXISTS Events (
                    Id TEXT PRIMARY KEY,
                    Timestamp TEXT NOT NULL,
                    Source INTEGER NOT NULL,
                    RawText TEXT NOT NULL,
                    Score INTEGER NOT NULL,
                    Level INTEGER NOT NULL,
                    MatchedRuleIds TEXT NOT NULL,
                    Explanation TEXT NULL,
                    ActionTaken INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS IX_Events_Level ON Events(Level);
                CREATE INDEX IF NOT EXISTS IX_Events_Timestamp ON Events(Timestamp);
                """;
            command.ExecuteNonQuery();

            _schemaReady = true;
        }
    }
}
