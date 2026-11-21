namespace cyberproj.Models;

public static class Roles
{
    public const string Administrator = "Administrator";
    public const string Kierownik = "Kierownik";
    public const string Redaktor = "Redaktor";
    public const string Czytelnik = "Czytelnik";

    public static readonly string[] All = { Administrator, Kierownik, Redaktor, Czytelnik };
    // Administrator to stałe konto ADMIN - nie można nadać tej roli nowym użytkownikom.
    public static readonly string[] Assignable = { Kierownik, Redaktor, Czytelnik };
}

public class AppUser
{
    public int Id { get; set; }
    public string Login { get; set; } = "";
    public string FullName { get; set; } = "";
    public string Role { get; set; } = Roles.Czytelnik;
    public string PasswordHash { get; set; } = "";
    public bool IsBlocked { get; set; }
    public bool MustChangePassword { get; set; }
    public DateTime PasswordChangedAtUtc { get; set; }
    public DateTime? OneTimePasswordExpiresAtUtc { get; set; }
    public int FailedLoginCount { get; set; }
    public DateTime? LockoutUntilUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public List<PasswordHistoryEntry> PasswordHistory { get; set; } = new();
}

public class PasswordHistoryEntry
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Hash { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }
}

/// <summary>Sesja po stronie serwera. Cookie zawiera tylko losowy identyfikator.</summary>
public class UserSession
{
    public string Id { get; set; } = "";
    public int UserId { get; set; }
    public AppUser User { get; set; } = null!;
    public DateTime CreatedAtUtc { get; set; }
    public DateTime LastActivityUtc { get; set; }
}

public class AppSettings
{
    public int Id { get; set; }
    public int MinPasswordLength { get; set; } = 15;          // wariant 6: 15
    public bool PassphrasePolicyEnabled { get; set; } = false; // wariant 6: fraza hasłowa (włącza admin)
    public int PasswordValidityDays { get; set; } = 0;         // 0 = hasło bezterminowe
    public int SessionIdleMinutes { get; set; } = 1;
}

public class Article
{
    public int Id { get; set; }
    public string Title { get; set; } = "";
    public string Content { get; set; } = "";
    public int AuthorId { get; set; }
    public string AuthorLogin { get; set; } = "";
    public bool IsPublished { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
