using Microsoft.Data.Sqlite;
using SafeVault.Models;
using SafeVault.Security;

namespace SafeVault.Data;

/// <summary>
/// Provides parameterized database access for SafeVault user records.
/// </summary>
public sealed class UserRepository : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly bool _ownsConnection;

    /// <summary>
    /// Initializes a repository backed by an open or closed <see cref="SqliteConnection"/>.
    /// </summary>
    public UserRepository(SqliteConnection connection, bool ownsConnection = false)
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
        _ownsConnection = ownsConnection;

        if (_connection.State != System.Data.ConnectionState.Open)
        {
            _connection.Open();
        }
    }

    /// <summary>
    /// Creates the Users table if it does not already exist.
    /// </summary>
    public void InitializeSchema()
    {
        using var command = _connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                Email TEXT NOT NULL UNIQUE
            );
            """;
        command.ExecuteNonQuery();
    }

    /// <summary>
    /// Validates user inputs and inserts a new user using parameterized SQL.
    /// </summary>
    public User CreateUser(string username, string email)
    {
        if (!InputSanitizer.TryValidateUsername(username, out string validUsername, out string usernameError))
        {
            throw new ArgumentException(usernameError, nameof(username));
        }

        if (!InputSanitizer.TryValidateEmail(email, out string validEmail, out string emailError))
        {
            throw new ArgumentException(emailError, nameof(email));
        }

        using var command = _connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Username, Email)
            VALUES (@Username, @Email);
            SELECT last_insert_rowid();
            """;
        command.Parameters.Add(new SqliteParameter("@Username", validUsername));
        command.Parameters.Add(new SqliteParameter("@Email", validEmail));

        int userId = Convert.ToInt32(command.ExecuteScalar());
        return new User(userId, validUsername, validEmail);
    }

    /// <summary>
    /// Retrieves a user by exact username using a parameterized query.
    /// </summary>
    public User? GetUserByUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email FROM Users WHERE Username = @Username;";
        command.Parameters.Add(new SqliteParameter("@Username", username.Trim()));

        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadUser(reader) : null;
    }

    /// <summary>
    /// Retrieves a user by exact normalized email using a parameterized query.
    /// </summary>
    public User? GetUserByEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return null;
        }

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email FROM Users WHERE Email = @Email;";
        command.Parameters.Add(new SqliteParameter("@Email", email.Trim().ToLowerInvariant()));

        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadUser(reader) : null;
    }

    /// <summary>
    /// Searches users by username substring with LIKE wildcard escaping and parameterization.
    /// </summary>
    public IReadOnlyList<User> SearchUsers(string searchTerm)
    {
        if (string.IsNullOrWhiteSpace(searchTerm))
        {
            return [];
        }

        string escaped = EscapeLikePattern(searchTerm.Trim());
        using var command = _connection.CreateCommand();
        command.CommandText = """
            SELECT UserID, Username, Email
            FROM Users
            WHERE Username LIKE @Pattern ESCAPE '\'
            ORDER BY UserID;
            """;
        command.Parameters.Add(new SqliteParameter("@Pattern", $"%{escaped}%"));

        var results = new List<User>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            results.Add(ReadUser(reader));
        }

        return results;
    }

    /// <summary>
    /// Returns all users stored in the Users table ordered by UserID.
    /// </summary>
    public IReadOnlyList<User> GetAllUsers()
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email FROM Users ORDER BY UserID;";

        var results = new List<User>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            results.Add(ReadUser(reader));
        }

        return results;
    }

    public void Dispose()
    {
        if (_ownsConnection)
        {
            _connection.Dispose();
        }
    }

    private static string EscapeLikePattern(string value)
    {
        return value
            .Replace(@"\", @"\\", StringComparison.Ordinal)
            .Replace("%", @"\%", StringComparison.Ordinal)
            .Replace("_", @"\_", StringComparison.Ordinal);
    }

    private static User ReadUser(SqliteDataReader reader)
    {
        return new User(
            reader.GetInt32(0),
            reader.GetString(1),
            reader.GetString(2));
    }
}
