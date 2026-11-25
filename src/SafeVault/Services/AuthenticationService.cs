using Microsoft.Data.Sqlite;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;

namespace SafeVault.Services;

/// <summary>
/// Handles user registration and credential verification using salted BCrypt password hashes.
/// </summary>
public sealed class AuthenticationService
{
    private const int SqliteConstraintErrorCode = 19;
    private const string InvalidCredentialsMessage = "Invalid username or password.";

    // Precomputed dummy hash reduces timing differences when a username does not exist.
    private static readonly string DummyPasswordHash = PasswordHasher.HashPassword("SafeVaultDummy#2026");

    private readonly UserRepository _repository;

    public AuthenticationService(UserRepository repository)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    }

    /// <summary>
    /// Validates registration inputs, hashes the password with BCrypt, and persists the user.
    /// </summary>
    public AuthResult Register(string? username, string? email, string? password, string role = UserRoles.User)
    {
        if (!InputSanitizer.TryValidateUsername(username, out string validUsername, out string usernameError))
        {
            return new AuthResult(false, null, usernameError);
        }

        if (!InputSanitizer.TryValidateEmail(email, out string validEmail, out string emailError))
        {
            return new AuthResult(false, null, emailError);
        }

        if (!PasswordHasher.ValidatePasswordStrength(password, out string passwordError))
        {
            return new AuthResult(false, null, passwordError);
        }

        if (!UserRoles.IsValid(role))
        {
            return new AuthResult(false, null, "Role must be 'admin' or 'user'.");
        }

        string normalizedRole = UserRoles.Normalize(role);
        string passwordHash = PasswordHasher.HashPassword(password!);

        try
        {
            User created = _repository.CreateUser(validUsername, validEmail, passwordHash, normalizedRole);
            return new AuthResult(true, ToAuthenticatedUser(created), null);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == SqliteConstraintErrorCode)
        {
            return new AuthResult(false, null, "Username or email is already registered.");
        }
    }

    /// <summary>
    /// Verifies a user's credentials against stored BCrypt password hashes.
    /// </summary>
    public AuthResult Login(string? username, string? password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return new AuthResult(false, null, InvalidCredentialsMessage);
        }

        if (!InputSanitizer.TryValidateUsername(username, out string validUsername, out _))
        {
            PasswordHasher.VerifyPassword(password, DummyPasswordHash);
            return new AuthResult(false, null, InvalidCredentialsMessage);
        }

        User? user = _repository.GetUserByUsername(validUsername);
        if (user is null || string.IsNullOrEmpty(user.PasswordHash))
        {
            PasswordHasher.VerifyPassword(password, DummyPasswordHash);
            return new AuthResult(false, null, InvalidCredentialsMessage);
        }

        if (!PasswordHasher.VerifyPassword(password, user.PasswordHash))
        {
            return new AuthResult(false, null, InvalidCredentialsMessage);
        }

        return new AuthResult(true, ToAuthenticatedUser(user), null);
    }

    private static AuthenticatedUser ToAuthenticatedUser(User user)
    {
        return new AuthenticatedUser(user.UserId, user.Username, user.Email, user.Role);
    }
}
