using SafeVault.Models;

namespace SafeVault.Security;

/// <summary>
/// Enforces role-based access control (RBAC) across application roles and protected routes.
/// </summary>
public static class AuthorizationService
{
    /// <summary>
    /// Returns true if the authenticated user holds the required role.
    /// </summary>
    public static bool HasRole(AuthenticatedUser? user, string requiredRole)
    {
        if (user is null || !UserRoles.IsValid(requiredRole))
        {
            return false;
        }

        return string.Equals(user.Role, requiredRole.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Returns true if the authenticated user holds any of the allowed roles.
    /// </summary>
    public static bool HasAnyRole(AuthenticatedUser? user, params string[] allowedRoles)
    {
        if (user is null || allowedRoles is null || allowedRoles.Length == 0)
        {
            return false;
        }

        foreach (string role in allowedRoles)
        {
            if (HasRole(user, role))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Evaluates whether the user is permitted to access the specified route (fail-closed for unknown or malformed routes).
    /// </summary>
    public static bool AuthorizeRoute(AuthenticatedUser? user, string route)
    {
        if (route is null || ContainsUnsafeRouteTokens(route))
        {
            return false;
        }

        string normalized = route.Trim().ToLowerInvariant().TrimEnd('/');
        return normalized switch
        {
            "" or "/login" or "/register" => true,
            "/vault" or "/profile" => HasAnyRole(user, UserRoles.Admin, UserRoles.User),
            "/admin" or "/admin/dashboard" or "/admin/users" => HasRole(user, UserRoles.Admin),
            _ => false
        };
    }

    private static bool ContainsUnsafeRouteTokens(string route)
    {
        foreach (char ch in route)
        {
            if (char.IsControl(ch))
            {
                return true;
            }
        }

        return route.Contains("..", StringComparison.Ordinal)
            || route.Contains('\\', StringComparison.Ordinal)
            || route.Contains("//", StringComparison.Ordinal)
            || route.Contains("%2e", StringComparison.OrdinalIgnoreCase)
            || route.Contains("%2f", StringComparison.OrdinalIgnoreCase)
            || route.Contains("%5c", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Throws <see cref="UnauthorizedAccessException"/> if the user lacks the required role.
    /// </summary>
    public static void EnsureAuthorized(AuthenticatedUser? user, string requiredRole)
    {
        if (!HasRole(user, requiredRole))
        {
            throw new UnauthorizedAccessException($"Access denied. Required role: {requiredRole}.");
        }
    }
}
