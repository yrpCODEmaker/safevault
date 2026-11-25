using Microsoft.Data.Sqlite;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;

namespace SafeVault.Services;

/// <summary>
/// Represents the outcome of processing a user registration form submission.
/// </summary>
public sealed record SubmissionResult(
    bool Success,
    User? User,
    string? SafeDisplayUsername,
    string? ErrorMessage);

/// <summary>
/// Coordinates input validation, persistence, and HTML-safe output formatting for form submissions.
/// </summary>
public sealed class FormSubmissionService
{
    private const int SqliteConstraintErrorCode = 19;
    private readonly UserRepository _repository;

    public FormSubmissionService(UserRepository repository)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    }

    /// <summary>
    /// Validates form fields and stores the user when valid, returning a safe result object.
    /// </summary>
    public SubmissionResult Submit(string? username, string? email)
    {
        if (!InputSanitizer.TryValidateUsername(username, out string validUsername, out string usernameError))
        {
            return new SubmissionResult(false, null, null, usernameError);
        }

        if (!InputSanitizer.TryValidateEmail(email, out string validEmail, out string emailError))
        {
            return new SubmissionResult(false, null, null, emailError);
        }

        try
        {
            User created = _repository.CreateUser(validUsername, validEmail);
            string safeDisplayUsername = InputSanitizer.SanitizeForHtml(created.Username);
            return new SubmissionResult(true, created, safeDisplayUsername, null);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == SqliteConstraintErrorCode)
        {
            return new SubmissionResult(false, null, null, "Username or email is already registered.");
        }
    }
}
