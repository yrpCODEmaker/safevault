using System.Net;
using System.Net.Mail;
using System.Text.RegularExpressions;

namespace SafeVault.Security;

/// <summary>
/// Provides input validation, injection detection, and HTML output encoding for SafeVault.
/// </summary>
public static partial class InputSanitizer
{
    public const int MinUsernameLength = 3;
    public const int MaxUsernameLength = 50;
    public const int MaxEmailLength = 100;

    [GeneratedRegex(@"^[a-zA-Z0-9_.-]{3,50}$", RegexOptions.CultureInvariant)]
    private static partial Regex UsernameAllowlistRegex();

    [GeneratedRegex(@"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$", RegexOptions.CultureInvariant)]
    private static partial Regex EmailAllowlistRegex();

    [GeneratedRegex(
        @"<\s*/?\s*(script|img|svg|iframe|object|embed|link|style|body|input|form|meta|base)\b|javascript\s*:|vbscript\s*:|data\s*:\s*text/html|\bon[a-z]+\s*=|<\s*[a-zA-Z][^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex XssPatternRegex();

    [GeneratedRegex(
        @"(--|/\*|\*/|['""`;\0])|\b(union\s+(all\s+)?select|select\s+.+\s+from|insert\s+into|update\s+.+\s+set|delete\s+from|drop\s+(table|database)|alter\s+table|exec(\s|\()|xp_cmdshell|waitfor\s+delay|sleep\s*\()\b|\bor\s+1\s*=\s*1\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SqlInjectionPatternRegex();

    /// <summary>
    /// Validates and normalizes a username using strict allowlist rules and injection checks.
    /// </summary>
    public static bool TryValidateUsername(string? input, out string sanitized, out string error)
    {
        sanitized = string.Empty;
        if (string.IsNullOrWhiteSpace(input))
        {
            error = "Username is required.";
            return false;
        }

        string trimmed = input.Trim();
        if (trimmed.Length is < MinUsernameLength or > MaxUsernameLength)
        {
            error = $"Username must be between {MinUsernameLength} and {MaxUsernameLength} characters.";
            return false;
        }

        if (ContainsControlChars(trimmed) || ContainsXssPattern(trimmed) || ContainsSqlInjectionPattern(trimmed))
        {
            error = "Username contains disallowed characters or potentially unsafe patterns.";
            return false;
        }

        if (!UsernameAllowlistRegex().IsMatch(trimmed))
        {
            error = "Username may only contain letters, digits, dots, underscores, and hyphens.";
            return false;
        }

        sanitized = trimmed;
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Validates and normalizes an email address, rejecting header injection, XSS, and SQLi payloads.
    /// </summary>
    public static bool TryValidateEmail(string? input, out string sanitized, out string error)
    {
        sanitized = string.Empty;
        if (string.IsNullOrWhiteSpace(input))
        {
            error = "Email is required.";
            return false;
        }

        string normalized = input.Trim().ToLowerInvariant();
        if (normalized.Length > MaxEmailLength)
        {
            error = $"Email must not exceed {MaxEmailLength} characters.";
            return false;
        }

        if (ContainsControlChars(normalized) ||
            normalized.Contains('<') ||
            normalized.Contains('>') ||
            normalized.Contains('\'') ||
            normalized.Contains('"') ||
            normalized.Contains(';') ||
            normalized.Contains("--", StringComparison.Ordinal) ||
            ContainsXssPattern(normalized) ||
            ContainsSqlInjectionPattern(normalized))
        {
            error = "Email contains disallowed characters or potentially unsafe patterns.";
            return false;
        }

        if (!EmailAllowlistRegex().IsMatch(normalized) || !IsValidMailAddress(normalized))
        {
            error = "Email format is invalid.";
            return false;
        }

        sanitized = normalized;
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// HTML-encodes untrusted text so it cannot execute as markup or script when rendered.
    /// </summary>
    public static string SanitizeForHtml(string? input)
    {
        return string.IsNullOrEmpty(input) ? string.Empty : WebUtility.HtmlEncode(input);
    }

    /// <summary>
    /// Returns true if the input matches common XSS vectors or raw HTML tag syntax.
    /// </summary>
    public static bool ContainsXssPattern(string? input)
    {
        return !string.IsNullOrWhiteSpace(input) && XssPatternRegex().IsMatch(input);
    }

    /// <summary>
    /// Returns true if the input matches common SQL injection tokens or keywords.
    /// </summary>
    public static bool ContainsSqlInjectionPattern(string? input)
    {
        return !string.IsNullOrWhiteSpace(input) && SqlInjectionPatternRegex().IsMatch(input);
    }

    private static bool ContainsControlChars(string value)
    {
        foreach (char ch in value)
        {
            if (char.IsControl(ch))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsValidMailAddress(string email)
    {
        int atIndex = email.IndexOf('@');
        if (atIndex <= 0 || atIndex == email.Length - 1)
        {
            return false;
        }

        string localPart = email[..atIndex];
        string domainPart = email[(atIndex + 1)..];
        if (localPart.StartsWith('.') || localPart.EndsWith('.') ||
            domainPart.StartsWith('.') || domainPart.EndsWith('.') ||
            email.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            var address = new MailAddress(email);
            return string.Equals(address.Address, email, StringComparison.OrdinalIgnoreCase);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
