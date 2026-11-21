using cyberproj.Data;
using cyberproj.Models;
using Microsoft.EntityFrameworkCore;

namespace cyberproj.Security;

public static class PasswordService
{
    private const int HistorySize = 5;

    /// <summary>Waliduje nowe hasło: polityka + różnica od aktualnego i poprzednich haseł.</summary>
    public static async Task<List<string>> ValidateNewAsync(AppDbContext db, AppUser user, string newPassword, AppSettings settings)
    {
        var errors = PasswordPolicy.Validate(newPassword, settings);
        if (errors.Count > 0) return errors;

        var hashes = new List<string> { user.PasswordHash };
        hashes.AddRange(await db.PasswordHistory
            .Where(h => h.UserId == user.Id)
            .OrderByDescending(h => h.Id)
            .Take(HistorySize)
            .Select(h => h.Hash)
            .ToListAsync());

        if (hashes.Any(h => PasswordHasher.Verify(newPassword, h)))
            errors.Add("Nowe hasło musi różnić się od poprzednich haseł.");

        return errors;
    }

    public static void SetPassword(AppUser user, string newPassword)
    {
        Archive(user);
        user.PasswordHash = PasswordHasher.Hash(newPassword);
        user.PasswordChangedAtUtc = DateTime.UtcNow;
        user.MustChangePassword = false;
        user.OneTimePasswordExpiresAtUtc = null;
    }

    /// <summary>Nadaje hasło jednorazowe (utworzenie konta / reset). Zwraca hasło jawne - do pokazania adminowi JEDEN raz.</summary>
    public static string AssignOneTimePassword(AppUser user)
    {
        Archive(user);
        var otp = OneTimePassword.Generate();
        user.PasswordHash = PasswordHasher.Hash(otp);
        user.PasswordChangedAtUtc = DateTime.UtcNow;
        user.MustChangePassword = true;
        user.OneTimePasswordExpiresAtUtc = DateTime.UtcNow.Add(OneTimePassword.Validity);
        user.FailedLoginCount = 0;
        user.LockoutUntilUtc = null;
        return otp;
    }

    private static void Archive(AppUser user)
    {
        if (!string.IsNullOrEmpty(user.PasswordHash))
            user.PasswordHistory.Add(new PasswordHistoryEntry { Hash = user.PasswordHash, CreatedAtUtc = DateTime.UtcNow });
    }
}
