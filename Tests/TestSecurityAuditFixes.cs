using Microsoft.Data.Sqlite;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;
using SafeVault.Services;

namespace SafeVault.Tests;

[TestFixture]
public class TestSecurityAuditFixes
{
    private SqliteConnection _connection = null!;
    private UserRepository _repository = null!;
    private AuthenticationService _authService = null!;
    private AdminDashboardService _adminService = null!;
    private FormSubmissionService _formService = null!;

    [SetUp]
    public void SetUp()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _repository = new UserRepository(_connection);
        _repository.InitializeSchema();
        _authService = new AuthenticationService(_repository);
        _adminService = new AdminDashboardService(_repository);
        _formService = new FormSubmissionService(_repository);

        _authService.Register("admin_root", "admin@safevault.local", "AdminPass123", UserRoles.Admin);
        _authService.Register("standard_user", "user@safevault.local", "UserPass123", UserRoles.User);
    }

    [TearDown]
    public void TearDown()
    {
        _repository.Dispose();
        _connection.Dispose();
    }

    [TestCase("'; UPDATE Users SET Role='admin' WHERE 1=1; --")]
    [TestCase("' UNION SELECT 1,'x','x@x.com','admin','h' --")]
    public void SqlInjectionPrivilegeEscalationAndStackedQueries_AreBlockedAcrossAllLayers(string payload)
    {
        User? byUsername = _repository.GetUserByUsername(payload);
        User? byEmail = _repository.GetUserByEmail(payload);
        IReadOnlyList<User> bySearch = _repository.SearchUsers(payload);
        AuthResult loginResult = _authService.Login(payload, "UserPass123");
        AuthResult registerResult = _authService.Register(payload, "evil@safevault.local", "StrongPass1", UserRoles.Admin);
        SubmissionResult formResult = _formService.Submit(payload, "evil@safevault.local");

        User? standardUser = _repository.GetUserByUsername("standard_user");
        IReadOnlyList<User> allUsers = _repository.GetAllUsers();

        Assert.Multiple(() =>
        {
            Assert.That(byUsername, Is.Null);
            Assert.That(byEmail, Is.Null);
            Assert.That(bySearch, Is.Empty);
            Assert.That(loginResult.Success, Is.False);
            Assert.That(registerResult.Success, Is.False);
            Assert.That(formResult.Success, Is.False);
            Assert.That(standardUser, Is.Not.Null);
            Assert.That(standardUser!.Role, Is.EqualTo(UserRoles.User));
            Assert.That(allUsers, Has.Count.EqualTo(2));
        });
    }

    [Test]
    public void SearchUsers_RejectsNullBytesAndOversizedQueries()
    {
        IReadOnlyList<User> nullByteResult = _repository.SearchUsers("standard\0");
        IReadOnlyList<User> oversizedResult = _repository.SearchUsers(new string('a', 101));

        Assert.Multiple(() =>
        {
            Assert.That(nullByteResult, Is.Empty);
            Assert.That(oversizedResult, Is.Empty);
        });
    }

    [Test]
    public void GetAdminDashboard_EncodesLegacyOrInjectedStoredXssPayloads()
    {
        using (var cmd = _connection.CreateCommand())
        {
            cmd.CommandText = """
                INSERT INTO Users (Username, Email, PasswordHash, Role)
                VALUES ('<script>alert(''stored'')</script>', 'stored<img src=x onerror=alert(1)>@evil.com', NULL, 'user');
                """;
            cmd.ExecuteNonQuery();
        }

        AuthenticatedUser admin = _authService.Login("admin_root", "AdminPass123").User!;
        AdminDashboardSnapshot snapshot = _adminService.GetAdminDashboard(admin);
        AuthenticatedUser storedRow = snapshot.Users.Single(u => u.Username.Contains("stored", StringComparison.Ordinal));

        Assert.Multiple(() =>
        {
            Assert.That(storedRow.Username, Does.Not.Contain("<"));
            Assert.That(storedRow.Username, Does.Not.Contain(">"));
            Assert.That(storedRow.Username, Does.Contain("&lt;script&gt;"));
            Assert.That(storedRow.Email, Does.Not.Contain("<"));
            Assert.That(storedRow.Email, Does.Not.Contain(">"));
            Assert.That(storedRow.Email, Does.Contain("&lt;img"));
        });
    }

    [Test]
    public void SanitizeUserContentAndUrl_NeutralizesXssVectorsAndAllowsSafeUrls()
    {
        string rawUgc = "Hello\0\u0007\r\n<script>alert(1)</script> & <img src=x onerror=\"alert(1)\">";
        string safeUgc = InputSanitizer.SanitizeUserContent(rawUgc);

        Assert.Multiple(() =>
        {
            Assert.That(safeUgc.Contains('\0'), Is.False);
            Assert.That(safeUgc.Contains('\u0007'), Is.False);
            Assert.That(safeUgc.Contains('\r'), Is.False);
            Assert.That(safeUgc, Does.Not.Contain("<"));
            Assert.That(safeUgc, Does.Not.Contain(">"));
            Assert.That(safeUgc, Does.Not.Contain("\""));
            Assert.That(safeUgc, Is.EqualTo("Hello\n&lt;script&gt;alert(1)&lt;/script&gt; &amp; &lt;img src=x onerror=&quot;alert(1)&quot;&gt;"));

            Assert.That(InputSanitizer.SanitizeUrl("javascript:alert(1)"), Is.Empty);
            Assert.That(InputSanitizer.SanitizeUrl("JaVaScRiPt:alert(1)"), Is.Empty);
            Assert.That(InputSanitizer.SanitizeUrl("data:text/html,<script>alert(1)</script>"), Is.Empty);
            Assert.That(InputSanitizer.SanitizeUrl("vbscript:msgbox(1)"), Is.Empty);
            Assert.That(InputSanitizer.SanitizeUrl("//evil.com/phish"), Is.Empty);

            Assert.That(InputSanitizer.SanitizeUrl("https://safevault.example/dashboard"), Is.EqualTo("https://safevault.example/dashboard"));
            Assert.That(InputSanitizer.SanitizeUrl("/vault"), Is.EqualTo("/vault"));
        });
    }

    [Test]
    public void PasswordHasher_RejectsPasswordsExceeding72Utf8BytesToPreventTruncationCollisions()
    {
        string exact72Bytes = "Aa1" + new string('x', 69);
        string ascii73Bytes = exact72Bytes + "y";
        string multibyte75Bytes = "Aa1" + new string('é', 36); // 39 chars, 75 UTF-8 bytes

        string hash72 = PasswordHasher.HashPassword(exact72Bytes);

        bool valid72 = PasswordHasher.ValidatePasswordStrength(exact72Bytes, out _);
        bool valid73 = PasswordHasher.ValidatePasswordStrength(ascii73Bytes, out string err73);
        bool validMultibyte = PasswordHasher.ValidatePasswordStrength(multibyte75Bytes, out string errMulti);
        AuthResult reg73 = _authService.Register("long_pass_user", "long@safevault.local", ascii73Bytes);

        Assert.Multiple(() =>
        {
            Assert.That(valid72, Is.True);
            Assert.That(valid73, Is.False);
            Assert.That(err73, Does.Contain("72"));
            Assert.That(validMultibyte, Is.False);
            Assert.That(errMulti, Does.Contain("72"));
            Assert.That(reg73.Success, Is.False);
            Assert.That(() => PasswordHasher.HashPassword(ascii73Bytes), Throws.TypeOf<ArgumentException>());
            Assert.That(PasswordHasher.VerifyPassword(exact72Bytes, hash72), Is.True);
            Assert.That(PasswordHasher.VerifyPassword(ascii73Bytes, hash72), Is.False);
            Assert.That(PasswordHasher.VerifyPassword(multibyte75Bytes, hash72), Is.False);
        });
    }

    [TestCase("/login/../admin")]
    [TestCase("/admin//dashboard")]
    [TestCase("/admin\\dashboard")]
    [TestCase("/admin/%2e%2e/admin")]
    [TestCase("/vault%2f..")]
    [TestCase("/admin\0")]
    public void AuthorizeRoute_DeniesPathTraversalAndMalformedRoutesEvenForAdmin(string malformedRoute)
    {
        AuthenticatedUser admin = _authService.Login("admin_root", "AdminPass123").User!;
        AuthenticatedUser regularUser = _authService.Login("standard_user", "UserPass123").User!;

        Assert.Multiple(() =>
        {
            Assert.That(AuthorizationService.AuthorizeRoute(admin, malformedRoute), Is.False);
            Assert.That(AuthorizationService.AuthorizeRoute(regularUser, malformedRoute), Is.False);
            Assert.That(AuthorizationService.AuthorizeRoute(null, malformedRoute), Is.False);
        });
    }
}
