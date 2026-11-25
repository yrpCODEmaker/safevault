using Microsoft.Data.Sqlite;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;
using SafeVault.Services;

namespace SafeVault.Tests;

[TestFixture]
public class TestInputValidation
{
    private SqliteConnection _connection = null!;
    private UserRepository _repository = null!;
    private FormSubmissionService _service = null!;

    [SetUp]
    public void SetUp()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _repository = new UserRepository(_connection);
        _repository.InitializeSchema();
        _repository.CreateUser("alice_admin", "alice@safevault.local");
        _repository.CreateUser("bob.user", "bob@safevault.local");
        _service = new FormSubmissionService(_repository);
    }

    [TearDown]
    public void TearDown()
    {
        _repository.Dispose();
        _connection.Dispose();
    }

    [Test]
    public void TestForSQLInjection()
    {
        string[] payloads =
        [
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE Users; --",
            "' UNION SELECT 1, 'evil', 'evil@evil.com' --",
            "1; DELETE FROM Users; --"
        ];

        foreach (string payload in payloads)
        {
            AssertSqlInjectionPayloadBlocked(payload);
        }

        IReadOnlyList<User> existingUsers = _repository.GetAllUsers();
        Assert.That(existingUsers, Has.Count.EqualTo(2));
    }

    [TestCase("' OR '1'='1")]
    [TestCase("admin'--")]
    [TestCase("'; DROP TABLE Users; --")]
    [TestCase("' UNION SELECT 1, 'evil', 'evil@evil.com' --")]
    [TestCase("1; DELETE FROM Users; --")]
    public void SqlInjectionPayloads_AreRejectedByValidatorsAndSafeInQueries(string payload)
    {
        AssertSqlInjectionPayloadBlocked(payload);
    }

    [Test]
    public void TestForXSS()
    {
        string[] payloads =
        [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg/onload=alert('xss')>",
            "\" onmouseover=\"alert(1)"
        ];

        foreach (string payload in payloads)
        {
            AssertXssPayloadBlockedAndEncoded(payload);
        }
    }

    [TestCase("<script>alert('XSS')</script>")]
    [TestCase("<img src=x onerror=alert(1)>")]
    [TestCase("javascript:alert(1)")]
    [TestCase("<svg/onload=alert('xss')>")]
    [TestCase("\" onmouseover=\"alert(1)")]
    public void XssPayloads_AreRejectedByValidatorsAndEncodedForHtml(string payload)
    {
        AssertXssPayloadBlockedAndEncoded(payload);
    }

    [Test]
    public void ValidInputs_PassValidationAndPersistToDatabase()
    {
        bool usernameOk = InputSanitizer.TryValidateUsername("  charlie_01  ", out string cleanUsername, out string usernameErr);
        bool emailOk = InputSanitizer.TryValidateEmail("  Charlie.01@SafeVault.IO  ", out string cleanEmail, out string emailErr);

        Assert.Multiple(() =>
        {
            Assert.That(usernameOk, Is.True);
            Assert.That(cleanUsername, Is.EqualTo("charlie_01"));
            Assert.That(usernameErr, Is.Empty);
            Assert.That(emailOk, Is.True);
            Assert.That(cleanEmail, Is.EqualTo("charlie.01@safevault.io"));
            Assert.That(emailErr, Is.Empty);
        });

        User created = _repository.CreateUser(cleanUsername, cleanEmail);
        User? byUsername = _repository.GetUserByUsername("charlie_01");
        User? byEmail = _repository.GetUserByEmail("charlie.01@safevault.io");
        IReadOnlyList<User> searched = _repository.SearchUsers("charlie");

        Assert.Multiple(() =>
        {
            Assert.That(created.UserId, Is.GreaterThan(0));
            Assert.That(byUsername, Is.EqualTo(created));
            Assert.That(byEmail, Is.EqualTo(created));
            Assert.That(searched, Has.Count.EqualTo(1));
            Assert.That(searched[0], Is.EqualTo(created));
        });
    }

    [Test]
    public void SearchUsers_EscapesLikeWildcardsSafely()
    {
        IReadOnlyList<User> wildcardSearch = _repository.SearchUsers("%");
        IReadOnlyList<User> underscoreSearch = _repository.SearchUsers("_");

        Assert.Multiple(() =>
        {
            Assert.That(wildcardSearch, Is.Empty);
            Assert.That(underscoreSearch, Has.Count.EqualTo(1));
            Assert.That(underscoreSearch[0].Username, Is.EqualTo("alice_admin"));
        });
    }

    [Test]
    public void FormSubmissionService_AcceptsValidInputAndRejectsMaliciousOrDuplicateInput()
    {
        SubmissionResult validResult = _service.Submit("dana-dev", "Dana@SafeVault.dev");
        SubmissionResult duplicateResult = _service.Submit("dana-dev", "other@safevault.dev");
        SubmissionResult sqliResult = _service.Submit("'; DROP TABLE Users; --", "dana@safevault.dev");
        SubmissionResult xssResult = _service.Submit("<script>alert(1)</script>", "xss@safevault.dev");

        Assert.Multiple(() =>
        {
            Assert.That(validResult.Success, Is.True);
            Assert.That(validResult.User, Is.Not.Null);
            Assert.That(validResult.SafeDisplayUsername, Is.EqualTo("dana-dev"));
            Assert.That(validResult.ErrorMessage, Is.Null);

            Assert.That(duplicateResult.Success, Is.False);
            Assert.That(duplicateResult.ErrorMessage, Is.Not.Null.And.Not.Empty);

            Assert.That(sqliResult.Success, Is.False);
            Assert.That(sqliResult.User, Is.Null);

            Assert.That(xssResult.Success, Is.False);
            Assert.That(xssResult.User, Is.Null);

            Assert.That(_repository.GetAllUsers(), Has.Count.EqualTo(3));
        });
    }

    private void AssertSqlInjectionPayloadBlocked(string payload)
    {
        bool usernameValid = InputSanitizer.TryValidateUsername(payload, out _, out _);
        bool emailValid = InputSanitizer.TryValidateEmail(payload, out _, out _);
        bool emailWithDomainValid = InputSanitizer.TryValidateEmail($"{payload}@evil.com", out _, out _);

        User? byUsername = _repository.GetUserByUsername(payload);
        User? byEmail = _repository.GetUserByEmail(payload);
        IReadOnlyList<User> bySearch = _repository.SearchUsers(payload);
        SubmissionResult submitResult = _service.Submit(payload, "attacker@evil.com");
        IReadOnlyList<User> allUsers = _repository.GetAllUsers();

        Assert.Multiple(() =>
        {
            Assert.That(usernameValid, Is.False, $"Username validator should reject: {payload}");
            Assert.That(emailValid, Is.False, $"Email validator should reject: {payload}");
            Assert.That(emailWithDomainValid, Is.False, $"Email validator should reject: {payload}@evil.com");
            Assert.That(byUsername, Is.Null, $"Parameterized username lookup leaked record for: {payload}");
            Assert.That(byEmail, Is.Null, $"Parameterized email lookup leaked record for: {payload}");
            Assert.That(bySearch, Is.Empty, $"Parameterized search leaked records for: {payload}");
            Assert.That(submitResult.Success, Is.False, $"Form submission should reject SQLi: {payload}");
            Assert.That(allUsers, Has.Count.EqualTo(2), $"Users table should remain intact after: {payload}");
        });
    }

    private void AssertXssPayloadBlockedAndEncoded(string payload)
    {
        bool usernameValid = InputSanitizer.TryValidateUsername(payload, out _, out _);
        bool emailValid = InputSanitizer.TryValidateEmail(payload, out _, out _);
        bool emailWithDomainValid = InputSanitizer.TryValidateEmail($"{payload}@evil.com", out _, out _);
        string encoded = InputSanitizer.SanitizeForHtml(payload);
        SubmissionResult submitResult = _service.Submit(payload, "attacker@evil.com");

        Assert.Multiple(() =>
        {
            Assert.That(usernameValid, Is.False, $"Username validator should reject XSS: {payload}");
            Assert.That(emailValid, Is.False, $"Email validator should reject XSS: {payload}");
            Assert.That(emailWithDomainValid, Is.False, $"Email validator should reject XSS: {payload}@evil.com");
            Assert.That(encoded, Does.Not.Contain("<"), $"Encoded output must not contain '<': {encoded}");
            Assert.That(encoded, Does.Not.Contain(">"), $"Encoded output must not contain '>': {encoded}");
            Assert.That(encoded, Does.Not.Contain("\""), $"Encoded output must not contain '\"': {encoded}");
            Assert.That(encoded, Does.Not.Contain("'"), $"Encoded output must not contain single quote: {encoded}");
            Assert.That(submitResult.Success, Is.False, $"Form submission should reject XSS: {payload}");
        });
    }
}
