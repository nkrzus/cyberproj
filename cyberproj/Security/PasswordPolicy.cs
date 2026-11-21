using cyberproj.Models;

namespace cyberproj.Security;

/// <summary>
/// Polityka haseł (wariant 6): minimalna długość + (opcjonalnie, włącza admin) fraza hasłowa.
/// Zgodnie z NIST SP 800-63B nie narzucamy reguł składu (wielkie litery, cyfry...) ani okresowej zmiany.
/// </summary>
public static class PasswordPolicy
{
    public const int MaxLength = 128;

    private static readonly HashSet<string> Banned = new(StringComparer.OrdinalIgnoreCase)
    {
        "passwordpassword", "password12345678", "123456789012345", "1234567890123456",
        "qwertyuiopasdfgh", "qwertyqwertyqwerty", "administrator123", "haslohaslohaslo",
        "aaaaaaaaaaaaaaaa", "1111111111111111", "zaq12wsxcde34rfv", "letmeinletmein123"
    };

    public static string[] Words(string password) =>
        password.Split(new[] { ' ', '-' }, StringSplitOptions.RemoveEmptyEntries);

    public static List<string> Validate(string password, AppSettings s)
    {
        var errors = new List<string>();

        if (password.Length < s.MinPasswordLength)
            errors.Add($"Hasło musi mieć co najmniej {s.MinPasswordLength} znaków.");
        if (password.Length > MaxLength)
            errors.Add($"Hasło może mieć maksymalnie {MaxLength} znaków.");

        if (s.PassphrasePolicyEnabled)
        {
            var words = Words(password);
            var distinct = words.Select(w => w.ToLowerInvariant()).Distinct().Count();
            if (words.Length < 3 || distinct < 3 || words.Any(w => w.Length < 2))
                errors.Add("Hasło musi być frazą: co najmniej 3 różne słowa (min. 2 znaki każde) oddzielone spacją lub myślnikiem.");
        }

        if (Banned.Contains(password))
            errors.Add("To hasło znajduje się na liście haseł zakazanych (zbyt popularne).");

        return errors;
    }

    public static List<string> Describe(AppSettings s)
    {
        var list = new List<string> { $"minimum {s.MinPasswordLength} znaków (spacje i znaki Unicode są dozwolone)" };
        if (s.PassphrasePolicyEnabled)
            list.Add("fraza hasłowa: co najmniej 3 różne słowa oddzielone spacją lub myślnikiem, np. „zielony rower - jesienny ranek”");
        list.Add("musi różnić się od poprzednich haseł");
        return list;
    }
}
