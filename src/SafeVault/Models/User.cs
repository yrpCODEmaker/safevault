using SafeVault.Security;

namespace SafeVault.Models;

/// <summary>
/// Represents a registered SafeVault user record.
/// </summary>
public sealed record User(
    int UserId,
    string Username,
    string Email,
    string Role = UserRoles.User,
    string? PasswordHash = null);
