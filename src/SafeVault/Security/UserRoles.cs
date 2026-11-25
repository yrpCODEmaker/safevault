namespace SafeVault.Security;

/// <summary>
/// Defines supported authorization roles and role validation helpers.
/// </summary>
public static class UserRoles
{
    public const string Admin = "admin";
    public const string User = "user";

    /// <summary>
    /// Returns true when the provided role matches a supported SafeVault role.
    /// </summary>
    public static bool IsValid(string? role)
    {
        if (string.IsNullOrWhiteSpace(role))
        {
            return false;
        }

        string trimmed = role.Trim();
        return string.Equals(trimmed, Admin, StringComparison.OrdinalIgnoreCase)
            || string.Equals(trimmed, User, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Validates and normalizes a role name to canonical lowercase form.
    /// </summary>
    public static string Normalize(string role)
    {
        if (!IsValid(role))
        {
            throw new ArgumentException("Role must be 'admin' or 'user'.", nameof(role));
        }

        return role.Trim().ToLowerInvariant();
    }
}
