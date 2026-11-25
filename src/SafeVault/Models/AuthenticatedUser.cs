namespace SafeVault.Models;

/// <summary>
/// Represents an authenticated SafeVault user projection without sensitive credential hashes.
/// </summary>
public sealed record AuthenticatedUser(
    int UserId,
    string Username,
    string Email,
    string Role);

/// <summary>
/// Represents the outcome of an authentication or registration attempt.
/// </summary>
public sealed record AuthResult(
    bool Success,
    AuthenticatedUser? User,
    string? ErrorMessage);
