using BCrypt.Net;

namespace SafeVault.Security;

/// <summary>
/// Validates password strength and performs salted BCrypt password hashing and verification.
/// </summary>
public static class PasswordHasher
{
    public const int MinPasswordLength = 8;
    public const int MaxPasswordLength = 128;
    public const int DefaultWorkFactor = 11;

    /// <summary>
    /// Validates minimum length and complexity requirements for user passwords.
    /// </summary>
    public static bool ValidatePasswordStrength(string? password, out string error)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            error = "Password is required.";
            return false;
        }

        if (password.Length is < MinPasswordLength or > MaxPasswordLength)
        {
            error = $"Password must be between {MinPasswordLength} and {MaxPasswordLength} characters.";
            return false;
        }

        bool hasUpper = false;
        bool hasLower = false;
        bool hasDigit = false;
        foreach (char ch in password)
        {
            if (char.IsUpper(ch))
            {
                hasUpper = true;
            }
            else if (char.IsLower(ch))
            {
                hasLower = true;
            }
            else if (char.IsDigit(ch))
            {
                hasDigit = true;
            }
        }

        if (!hasUpper || !hasLower || !hasDigit)
        {
            error = "Password must contain at least one uppercase letter, one lowercase letter, and one digit.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Hashes a plaintext password using BCrypt with a random per-password salt.
    /// </summary>
    public static string HashPassword(string password, int workFactor = DefaultWorkFactor)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("Password cannot be null or whitespace.", nameof(password));
        }

        return BCrypt.Net.BCrypt.HashPassword(password, workFactor);
    }

    /// <summary>
    /// Verifies a plaintext password against a stored BCrypt hash, returning false on mismatch or invalid hashes.
    /// </summary>
    public static bool VerifyPassword(string? password, string? passwordHash)
    {
        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(passwordHash))
        {
            return false;
        }

        try
        {
            return BCrypt.Net.BCrypt.Verify(password, passwordHash);
        }
        catch (SaltParseException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
