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
                Email TEXT NOT NULL UNIQUE,
                PasswordHash TEXT NULL,
                Role TEXT NOT NULL DEFAULT 'user'
            );
            """;
        command.ExecuteNonQuery();
    }

    /// <summary>
    /// Validates user inputs and inserts a new user using parameterized SQL with default role.
    /// </summary>
    public User CreateUser(string username, string email)
    {
        return CreateUser(username, email, passwordHash: null, role: UserRoles.User);
    }

    /// <summary>
    /// Validates user inputs and inserts a new user with password hash and role using parameterized SQL.
    /// </summary>
    public User CreateUser(string username, string email, string? passwordHash, string role = UserRoles.User)
    {
        if (!InputSanitizer.TryValidateUsername(username, out string validUsername, out string usernameError))
        {
            throw new ArgumentException(usernameError, nameof(username));
        }

        if (!InputSanitizer.TryValidateEmail(email, out string validEmail, out string emailError))
        {
            throw new ArgumentException(emailError, nameof(email));
        }

        string normalizedRole = UserRoles.Normalize(role);

        using var command = _connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            VALUES (@Username, @Email, @PasswordHash, @Role);
            SELECT last_insert_rowid();
            """;
        command.Parameters.Add(new SqliteParameter("@Username", validUsername));
        command.Parameters.Add(new SqliteParameter("@Email", validEmail));
        command.Parameters.Add(new SqliteParameter("@PasswordHash", (object?)passwordHash ?? DBNull.Value));
        command.Parameters.Add(new SqliteParameter("@Role", normalizedRole));

        int userId = Convert.ToInt32(command.ExecuteScalar());
        return new User(userId, validUsername, validEmail, normalizedRole, passwordHash);
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
        command.CommandText = """
            SELECT UserID, Username, Email, Role, PasswordHash
            FROM Users
            WHERE Username = @Username;
            """;
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
        command.CommandText = """
            SELECT UserID, Username, Email, Role, PasswordHash
            FROM Users
            WHERE Email = @Email;
            """;
        command.Parameters.Add(new SqliteParameter("@Email", email.Trim().ToLowerInvariant()));

        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadUser(reader) : null;
    }

    /// <summary>
    /// Searches users by username substring with LIKE wildcard escaping and parameterization.
    /// </summary>
    public IReadOnlyList<User> SearchUsers(string searchTerm)
    {
        if (string.IsNullOrWhiteSpace(searchTerm) || searchTerm.Contains('\0', StringComparison.Ordinal))
        {
            return [];
        }

        string trimmed = searchTerm.Trim();
        if (trimmed.Length > 100)
        {
            return [];
        }

        string escaped = EscapeLikePattern(trimmed);
        using var command = _connection.CreateCommand();
        command.CommandText = """
            SELECT UserID, Username, Email, Role, PasswordHash
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
        command.CommandText = """
            SELECT UserID, Username, Email, Role, PasswordHash
            FROM Users
            ORDER BY UserID;
            """;

        var results = new List<User>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            results.Add(ReadUser(reader));
        }

        return results;
    }

    /// <summary>
    /// Updates the role of an existing user using a parameterized UPDATE statement.
    /// </summary>
    public bool UpdateUserRole(int userId, string newRole)
    {
        string normalizedRole = UserRoles.Normalize(newRole);

        using var command = _connection.CreateCommand();
        command.CommandText = """
            UPDATE Users
            SET Role = @Role
            WHERE UserID = @UserId;
            """;
        command.Parameters.Add(new SqliteParameter("@Role", normalizedRole));
        command.Parameters.Add(new SqliteParameter("@UserId", userId));

        return command.ExecuteNonQuery() > 0;
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
            reader.GetString(2),
            reader.GetString(3),
            reader.IsDBNull(4) ? null : reader.GetString(4));
    }
}
