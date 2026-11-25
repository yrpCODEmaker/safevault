using Microsoft.Data.Sqlite;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;
using SafeVault.Services;

namespace SafeVault.Tests;

[TestFixture]
public class TestAuthenticationAndAuthorization
{
    private SqliteConnection _connection = null!;
    private UserRepository _repository = null!;
    private AuthenticationService _authService = null!;
    private AdminDashboardService _adminService = null!;

    [SetUp]
    public void SetUp()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _repository = new UserRepository(_connection);
        _repository.InitializeSchema();
        _authService = new AuthenticationService(_repository);
        _adminService = new AdminDashboardService(_repository);
    }

    [TearDown]
    public void TearDown()
    {
        _repository.Dispose();
        _connection.Dispose();
    }

    [Test]
    public void Register_HashesPasswordWithBCryptAndAllowsValidLogin()
    {
        const string plainPassword = "VaultPassword123";
        AuthResult regResult = _authService.Register("alice_admin", "alice@safevault.local", plainPassword, UserRoles.Admin);

        Assert.Multiple(() =>
        {
            Assert.That(regResult.Success, Is.True);
            Assert.That(regResult.User, Is.Not.Null);
            Assert.That(regResult.User!.Username, Is.EqualTo("alice_admin"));
            Assert.That(regResult.User.Role, Is.EqualTo(UserRoles.Admin));
            Assert.That(regResult.ErrorMessage, Is.Null);
        });

        User? stored = _repository.GetUserByUsername("alice_admin");
        Assert.Multiple(() =>
        {
            Assert.That(stored, Is.Not.Null);
            Assert.That(stored!.PasswordHash, Is.Not.Null.And.Not.Empty);
            Assert.That(stored.PasswordHash, Does.StartWith("$2"));
            Assert.That(stored.PasswordHash, Is.Not.EqualTo(plainPassword));
            Assert.That(PasswordHasher.VerifyPassword(plainPassword, stored.PasswordHash), Is.True);
        });

        AuthResult loginResult = _authService.Login("alice_admin", plainPassword);
        Assert.Multiple(() =>
        {
            Assert.That(loginResult.Success, Is.True);
            Assert.That(loginResult.User, Is.EqualTo(regResult.User));
            Assert.That(loginResult.ErrorMessage, Is.Null);
        });
    }

    [TestCase("short1A")]
    [TestCase("alllowercase123")]
    [TestCase("ALLUPPERCASE123")]
    [TestCase("NoDigitsHere")]
    [TestCase("   ")]
    public void Register_RejectsWeakPasswords(string weakPassword)
    {
        AuthResult result = _authService.Register("valid_user", "valid@safevault.local", weakPassword);

        Assert.Multiple(() =>
        {
            Assert.That(result.Success, Is.False);
            Assert.That(result.User, Is.Null);
            Assert.That(result.ErrorMessage, Is.Not.Null.And.Not.Empty);
            Assert.That(_repository.GetAllUsers(), Is.Empty);
        });
    }

    [TestCase("superadmin")]
    [TestCase("moderator")]
    [TestCase("")]
    public void Register_RejectsInvalidRolesAndDuplicates(string invalidRole)
    {
        AuthResult invalidRoleResult = _authService.Register("valid_user", "valid@safevault.local", "StrongPass1", invalidRole);
        AuthResult first = _authService.Register("bob_user", "bob@safevault.local", "StrongPass1", UserRoles.User);
        AuthResult duplicateUsername = _authService.Register("bob_user", "bob2@safevault.local", "StrongPass1", UserRoles.User);
        AuthResult duplicateEmail = _authService.Register("bob_two", "bob@safevault.local", "StrongPass1", UserRoles.User);

        Assert.Multiple(() =>
        {
            Assert.That(invalidRoleResult.Success, Is.False);
            Assert.That(first.Success, Is.True);
            Assert.That(duplicateUsername.Success, Is.False);
            Assert.That(duplicateEmail.Success, Is.False);
            Assert.That(_repository.GetAllUsers(), Has.Count.EqualTo(1));
        });
    }

    [TestCase("alice_admin", "WrongPassword1")]
    [TestCase("nonexistent_user", "StrongPass1")]
    [TestCase("' OR '1'='1", "StrongPass1")]
    [TestCase("admin'--", "StrongPass1")]
    [TestCase("", "StrongPass1")]
    [TestCase("alice_admin", "")]
    public void Login_FailsWithGenericErrorForInvalidCredentialsOrSqlInjection(string username, string password)
    {
        _authService.Register("alice_admin", "alice@safevault.local", "StrongPass1", UserRoles.Admin);

        AuthResult result = _authService.Login(username, password);

        Assert.Multiple(() =>
        {
            Assert.That(result.Success, Is.False);
            Assert.That(result.User, Is.Null);
            Assert.That(result.ErrorMessage, Is.EqualTo("Invalid username or password."));
        });
    }

    [Test]
    public void AuthorizeRoute_EnforcesRoleBasedAccessControlAndFailClosedUnknownRoutes()
    {
        AuthenticatedUser admin = _authService.Register("admin_one", "admin@safevault.local", "StrongPass1", UserRoles.Admin).User!;
        AuthenticatedUser regularUser = _authService.Register("user_one", "user@safevault.local", "StrongPass1", UserRoles.User).User!;

        Assert.Multiple(() =>
        {
            Assert.That(AuthorizationService.AuthorizeRoute(admin, "/admin"), Is.True);
            Assert.That(AuthorizationService.AuthorizeRoute(admin, "/admin/dashboard"), Is.True);
            Assert.That(AuthorizationService.AuthorizeRoute(admin, "/admin/users"), Is.True);
            Assert.That(AuthorizationService.AuthorizeRoute(admin, "/vault"), Is.True);
            Assert.That(AuthorizationService.AuthorizeRoute(admin, "/profile"), Is.True);
            Assert.That(AuthorizationService.AuthorizeRoute(admin, "/unknown"), Is.False);

            Assert.That(AuthorizationService.AuthorizeRoute(regularUser, "/vault"), Is.True);
            Assert.That(AuthorizationService.AuthorizeRoute(regularUser, "/profile"), Is.True);
            Assert.That(AuthorizationService.AuthorizeRoute(regularUser, "/login"), Is.True);
            Assert.That(AuthorizationService.AuthorizeRoute(regularUser, "/admin"), Is.False);
            Assert.That(AuthorizationService.AuthorizeRoute(regularUser, "/admin/dashboard"), Is.False);
            Assert.That(AuthorizationService.AuthorizeRoute(regularUser, "/admin/users"), Is.False);
            Assert.That(AuthorizationService.AuthorizeRoute(regularUser, "/unknown"), Is.False);

            Assert.That(AuthorizationService.AuthorizeRoute(null, "/"), Is.True);
            Assert.That(AuthorizationService.AuthorizeRoute(null, "/login"), Is.True);
            Assert.That(AuthorizationService.AuthorizeRoute(null, "/register"), Is.True);
            Assert.That(AuthorizationService.AuthorizeRoute(null, "/vault"), Is.False);
            Assert.That(AuthorizationService.AuthorizeRoute(null, "/profile"), Is.False);
            Assert.That(AuthorizationService.AuthorizeRoute(null, "/admin"), Is.False);
            Assert.That(AuthorizationService.AuthorizeRoute(null, "/admin/dashboard"), Is.False);
        });
    }

    [Test]
    public void AdminDashboardService_AllowsAdminAndDeniesUserOrAnonymous()
    {
        AuthenticatedUser admin = _authService.Register("admin_one", "admin@safevault.local", "StrongPass1", UserRoles.Admin).User!;
        AuthenticatedUser regularUser = _authService.Register("user_one", "user@safevault.local", "StrongPass1", UserRoles.User).User!;

        AdminDashboardSnapshot snapshot = _adminService.GetAdminDashboard(admin);

        Assert.Multiple(() =>
        {
            Assert.That(snapshot.TotalUsers, Is.EqualTo(2));
            Assert.That(snapshot.Users, Has.Count.EqualTo(2));
            Assert.That(snapshot.Users.All(u => u.GetType() == typeof(AuthenticatedUser)), Is.True);
            Assert.That(() => _adminService.GetAdminDashboard(regularUser), Throws.TypeOf<UnauthorizedAccessException>());
            Assert.That(() => _adminService.GetAdminDashboard(null), Throws.TypeOf<UnauthorizedAccessException>());
        });
    }

    [Test]
    public void AdminDashboardService_AssignRolePermitsAdminPromotionAndBlocksUnauthorizedUsers()
    {
        AuthenticatedUser admin = _authService.Register("admin_one", "admin@safevault.local", "StrongPass1", UserRoles.Admin).User!;
        AuthenticatedUser regularUser = _authService.Register("user_one", "user@safevault.local", "StrongPass1", UserRoles.User).User!;

        Assert.Multiple(() =>
        {
            Assert.That(() => _adminService.AssignRole(regularUser, admin.UserId, UserRoles.User), Throws.TypeOf<UnauthorizedAccessException>());
            Assert.That(() => _adminService.AssignRole(null, regularUser.UserId, UserRoles.Admin), Throws.TypeOf<UnauthorizedAccessException>());
        });

        bool updated = _adminService.AssignRole(admin, regularUser.UserId, UserRoles.Admin);
        AuthResult relogin = _authService.Login("user_one", "StrongPass1");

        Assert.Multiple(() =>
        {
            Assert.That(updated, Is.True);
            Assert.That(relogin.Success, Is.True);
            Assert.That(relogin.User!.Role, Is.EqualTo(UserRoles.Admin));
            Assert.That(AuthorizationService.AuthorizeRoute(relogin.User, "/admin/dashboard"), Is.True);
            Assert.That(_adminService.GetAdminDashboard(relogin.User).TotalUsers, Is.EqualTo(2));
        });
    }
}
