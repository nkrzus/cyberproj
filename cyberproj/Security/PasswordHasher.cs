namespace cyberproj.Security;

/// <summary>
/// bcrypt (BCrypt.Net-Next) - wolny algorytm do haseł, sól generowana losowo i zapisywana w hashu.
/// "Enhanced" = wstępny hash SHA-384 (omija limit 72 bajtów bcrypt, ważne dla długich fraz hasłowych).
/// </summary>
public static class PasswordHasher
{
    private const int WorkFactor = 11;

    public static string Hash(string password) =>
        BCrypt.Net.BCrypt.EnhancedHashPassword(password, WorkFactor);

    public static bool Verify(string password, string hash)
    {
        try { return BCrypt.Net.BCrypt.EnhancedVerify(password, hash); }
        catch (Exception) { return false; }
    }

    // Używany przy nieistniejącym loginie, żeby czas odpowiedzi nie zdradzał, czy login istnieje.
    public static readonly string DummyHash = Hash("hasło-do-wyrównania-czasu-odpowiedzi");
}
