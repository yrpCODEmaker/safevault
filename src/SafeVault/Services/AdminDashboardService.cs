using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;

namespace SafeVault.Services;

/// <summary>
/// Provides sanitized user summaries for authorized administrators without exposing password hashes.
/// </summary>
public sealed record AdminDashboardSnapshot(
    int TotalUsers,
    IReadOnlyList<AuthenticatedUser> Users);

/// <summary>
/// Exposes role-protected administrative operations gated to the admin role.
/// </summary>
public sealed class AdminDashboardService
{
    private readonly UserRepository _repository;

    public AdminDashboardService(UserRepository repository)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    }

    /// <summary>
    /// Returns a dashboard snapshot of registered users for administrators only.
    /// </summary>
    public AdminDashboardSnapshot GetAdminDashboard(AuthenticatedUser? currentUser)
    {
        AuthorizationService.EnsureAuthorized(currentUser, UserRoles.Admin);

        IReadOnlyList<User> allUsers = _repository.GetAllUsers();
        var summaries = new List<AuthenticatedUser>(allUsers.Count);
        foreach (User user in allUsers)
        {
            summaries.Add(new AuthenticatedUser(
                user.UserId,
                InputSanitizer.SanitizeForHtml(user.Username),
                InputSanitizer.SanitizeForHtml(user.Email),
                user.Role));
        }

        return new AdminDashboardSnapshot(summaries.Count, summaries);
    }

    /// <summary>
    /// Assigns a new role to a target user when requested by an authorized administrator.
    /// </summary>
    public bool AssignRole(AuthenticatedUser? currentUser, int targetUserId, string newRole)
    {
        AuthorizationService.EnsureAuthorized(currentUser, UserRoles.Admin);

        string normalizedRole = UserRoles.Normalize(newRole);
        return _repository.UpdateUserRole(targetUserId, normalizedRole);
    }
}
