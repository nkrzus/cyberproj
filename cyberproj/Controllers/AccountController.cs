using cyberproj.Data;
using cyberproj.Models;
using cyberproj.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace cyberproj.Controllers;

public class AccountController : Controller
{
    private const int MaxFailedAttempts = 5;
    private static readonly TimeSpan LockoutTime = TimeSpan.FromMinutes(15);

    private readonly AppDbContext _db;
    public AccountController(AppDbContext db) => _db = db;

    // ---------- Logowanie ----------

    [HttpGet, AllowAnonymous]
    public IActionResult Login(string? reason)
    {
        if (User.Identity?.IsAuthenticated == true) return RedirectToAction("Index", "Home");
        ViewBag.Info = reason switch
        {
            "timeout" => "Zostałeś wylogowany z powodu bezczynności.",
            "expired" => "Sesja wygasła. Zaloguj się ponownie.",
            "logout" => "Wylogowano pomyślnie.",
            _ => null
        };
        return View(new LoginViewModel());
    }

    [HttpPost, AllowAnonymous]
    public async Task<IActionResult> Login(LoginViewModel m)
    {
        if (!ModelState.IsValid) return View(m);

        const string generic = "Login lub hasło niepoprawne";
        var now = DateTime.UtcNow;
        var login = m.Login.Trim();

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Login == login);

        // Weryfikacja zawsze (także dla nieistniejącego loginu) - wyrównanie czasu odpowiedzi
        bool passwordOk = PasswordHasher.Verify(m.Password, user?.PasswordHash ?? PasswordHasher.DummyHash);
        bool locked = user?.LockoutUntilUtc > now;

        if (user == null || user.IsBlocked || locked || !passwordOk)
        {
            if (user != null && !user.IsBlocked && !locked)
            {
                user.FailedLoginCount++;
                if (user.FailedLoginCount >= MaxFailedAttempts)
                {
                    user.LockoutUntilUtc = now.Add(LockoutTime);
                    user.FailedLoginCount = 0;
                }
                await _db.SaveChangesAsync();
            }
            // Ten sam komunikat dla: brak konta, złe hasło, konto zablokowane, czasowa blokada
            ModelState.AddModelError("", generic);
            m.Password = "";
            return View(m);
        }

        if (user.OneTimePasswordExpiresAtUtc != null && user.OneTimePasswordExpiresAtUtc < now)
        {
            ModelState.AddModelError("", "Hasło jednorazowe wygasło. Skontaktuj się z administratorem.");
            m.Password = "";
            return View(m);
        }

        var settings = await _db.GetSettingsAsync();
        user.FailedLoginCount = 0;
        user.LockoutUntilUtc = null;

        // Wygaśnięcie ważności hasła => wymuszona zmiana
        if (!user.MustChangePassword && settings.PasswordValidityDays > 0 &&
            user.PasswordChangedAtUtc.AddDays(settings.PasswordValidityDays) < now)
            user.MustChangePassword = true;

        var session = new UserSession
        {
            Id = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)), // nowy, losowy ID przy każdym logowaniu
            UserId = user.Id,
            CreatedAtUtc = now,
            LastActivityUtc = now
        };
        _db.Sessions.Add(session);
        var cutoff = now.AddDays(-1);
        _db.Sessions.RemoveRange(_db.Sessions.Where(s => s.UserId == user.Id && s.LastActivityUtc < cutoff));
        await _db.SaveChangesAsync();

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            SessionHelper.BuildPrincipal(user, session.Id));

        return user.MustChangePassword
            ? RedirectToAction(nameof(FirstLogin))
            : RedirectToAction("Index", "Home");
    }

    // ---------- Wylogowanie ----------

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        var sid = User.FindFirst(AuthConstants.SessionIdClaim)?.Value;
        if (sid != null)
        {
            var s = await _db.Sessions.FirstOrDefaultAsync(x => x.Id == sid);
            if (s != null) { _db.Sessions.Remove(s); await _db.SaveChangesAsync(); }
        }
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction(nameof(Login), new { reason = "logout" });
    }

    // ---------- Pierwsze logowanie (wymuszona zmiana hasła) ----------

    [HttpGet]
    public async Task<IActionResult> FirstLogin()
    {
        var user = await CurrentUserAsync();
        if (user == null || !user.MustChangePassword) return RedirectToAction("Index", "Home");
        await FillHint();
        ViewBag.Forced = true;
        return View("ChangePassword", new ChangePasswordViewModel());
    }

    [HttpPost]
    public async Task<IActionResult> FirstLogin(ChangePasswordViewModel m)
    {
        var user = await CurrentUserAsync();
        if (user == null || !user.MustChangePassword) return RedirectToAction("Index", "Home");
        return await ApplyChange(user, m, forced: true);
    }

    // ---------- Zmiana hasła (wymaga starego hasła) ----------

    [HttpGet]
    public async Task<IActionResult> ChangePassword()
    {
        await FillHint();
        ViewBag.Forced = false;
        return View(new ChangePasswordViewModel());
    }

    [HttpPost]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel m)
    {
        var user = await CurrentUserAsync();
        if (user == null) return RedirectToAction(nameof(Login));

        if (string.IsNullOrEmpty(m.OldPassword) || !PasswordHasher.Verify(m.OldPassword, user.PasswordHash))
            ModelState.AddModelError(nameof(m.OldPassword), "Stare hasło jest niepoprawne.");

        return await ApplyChange(user, m, forced: false);
    }

    private async Task<IActionResult> ApplyChange(AppUser user, ChangePasswordViewModel m, bool forced)
    {
        var settings = await _db.GetSettingsAsync();
        ViewBag.Forced = forced;
        ViewBag.Hint = PasswordPolicy.Describe(settings);

        if (ModelState.IsValid)
        {
            foreach (var e in await PasswordService.ValidateNewAsync(_db, user, m.NewPassword, settings))
                ModelState.AddModelError(nameof(m.NewPassword), e);
        }

        if (!ModelState.IsValid)
        {
            m.OldPassword = m.NewPassword = m.ConfirmPassword = "";
            return View("ChangePassword", m);
        }

        PasswordService.SetPassword(user, m.NewPassword);

        // Unieważnij pozostałe sesje tego użytkownika
        var sid = User.FindFirst(AuthConstants.SessionIdClaim)?.Value;
        _db.Sessions.RemoveRange(_db.Sessions.Where(s => s.UserId == user.Id && s.Id != sid));
        await _db.SaveChangesAsync();

        TempData["Success"] = "Hasło zostało zmienione.";
        return RedirectToAction("Index", "Home");
    }

    // ---------- Helpers ----------

    private Task<AppUser?> CurrentUserAsync() =>
        _db.Users.Include(u => u.PasswordHistory).FirstOrDefaultAsync(u => u.Id == User.UserId());

    private async Task FillHint() => ViewBag.Hint = PasswordPolicy.Describe(await _db.GetSettingsAsync());
}
