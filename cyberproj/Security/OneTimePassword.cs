using System.Security.Cryptography;

namespace cyberproj.Security;

/// <summary>Wariant 6: 12 znaków (litery, cyfry, znaki specjalne), ważne 48 h.</summary>
public static class OneTimePassword
{
    public const int Length = 12;
    public static readonly TimeSpan Validity = TimeSpan.FromHours(48);

    private const string Lower = "abcdefghijklmnopqrstuvwxyz";
    private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Digits = "0123456789";
    private const string Special = "!@#$%^*-_+=?";

    public static string Generate()
    {
        var all = Lower + Upper + Digits + Special;
        var chars = new List<char>
        {
            Pick(Lower), Pick(Upper), Pick(Digits), Pick(Special)
        };
        while (chars.Count < Length) chars.Add(Pick(all));

        // tasowanie Fisher-Yates z kryptograficznym RNG
        for (int i = chars.Count - 1; i > 0; i--)
        {
            int j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }
        return new string(chars.ToArray());
    }

    private static char Pick(string set) => set[RandomNumberGenerator.GetInt32(set.Length)];
}
