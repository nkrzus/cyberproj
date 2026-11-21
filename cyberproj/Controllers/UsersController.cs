using cyberproj.Data;
using cyberproj.Models;
using cyberproj.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace cyberproj.Controllers;

// Podgląd listy: Administrator i Kierownik. Każda akcja zmieniająca dane wymaga users.manage (sprawdzane po stronie serwera).
[Authorize(Policy = Permissions.UsersView)]
public class UsersController : Controller
{
    private readonly AppDbContext _db;
    public UsersController(AppDbContext db) => _db = db;

    public async Task<IActionResult> Index() =>
        View(await _db.Users.AsNoTracking().OrderBy(u => u.Login).ToListAsync());

    // ---------- Dodawanie ----------

    [HttpGet, Authorize(Policy = Permissions.UsersManage)]
    public IActionResult Create() => View(new CreateUserViewModel());

    [HttpPost, Authorize(Policy = Permissions.UsersManage)]
    public async Task<IActionResult> Create(CreateUserViewModel m)
    {
        m.Login = (m.Login ?? "").Trim();
        if (!Roles.Assignable.Contains(m.Role))
            ModelState.AddModelError(nameof(m.Role), "Nieprawidłowa rola.");
        if (m.Login.Length > 0 && await _db.Users.AnyAsync(u => u.Login == m.Login))
            ModelState.AddModelError(nameof(m.Login), "Użytkownik o takim loginie już istnieje.");
        if (!ModelState.IsValid) return View(m);

        var user = new AppUser
        {
            Login = m.Login,
            FullName = m.FullName.Trim(),
            Role = m.Role,
            CreatedAtUtc = DateTime.UtcNow
        };
        var otp = PasswordService.AssignOneTimePassword(user);
        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        ShowOtp(user, otp);
        return RedirectToAction(nameof(Index));
    }

    // ---------- Edycja ----------

    [HttpGet, Authorize(Policy = Permissions.UsersManage)]
    public async Task<IActionResult> Edit(int id)
    {
        var u = await _db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id);
        if (u == null) return NotFound();
        if (IsAdminAccount(u)) return Protected();
        return View(new EditUserViewModel { Id = u.Id, Login = u.Login, FullName = u.FullName, Role = u.Role });
    }

    [HttpPost, Authorize(Policy = Permissions.UsersManage)]
    public async Task<IActionResult> Edit(int id, EditUserViewModel m)
    {
        var u = await _db.Users.FirstOrDefaultAsync(x => x.Id == id);
        if (u == null) return NotFound();
        if (IsAdminAccount(u)) return Protected();

        m.Id = u.Id; m.Login = u.Login;
        if (!Roles.Assignable.Contains(m.Role))
            ModelState.AddModelError(nameof(m.Role), "Nieprawidłowa rola.");
        if (!ModelState.IsValid) return View(m);

        u.FullName = m.FullName.Trim();
        u.Role = m.Role;
        await _db.SaveChangesAsync();
        TempData["Success"] = $"Zapisano zmiany użytkownika {u.Login}.";
        return RedirectToAction(nameof(Index));
    }

    // ---------- Blokowanie / odblokowanie ----------

    [HttpPost, Authorize(Policy = Permissions.UsersManage)]
    public async Task<IActionResult> ToggleBlock(int id)
    {
        var u = await _db.Users.FirstOrDefaultAsync(x => x.Id == id);
        if (u == null) return NotFound();
        if (IsAdminAccount(u) || u.Id == User.UserId()) return Protected();

        u.IsBlocked = !u.IsBlocked;
        if (u.IsBlocked)
            _db.Sessions.RemoveRange(_db.Sessions.Where(s => s.UserId == u.Id)); // natychmiastowe wylogowanie
        await _db.SaveChangesAsync();
        TempData["Success"] = u.IsBlocked ? $"Zablokowano konto {u.Login}." : $"Odblokowano konto {u.Login}.";
        return RedirectToAction(nameof(Index));
    }

    // ---------- Reset hasła (nowe hasło jednorazowe) ----------

    [HttpPost, Authorize(Policy = Permissions.UsersManage)]
    public async Task<IActionResult> ResetPassword(int id)
    {
        var u = await _db.Users.FirstOrDefaultAsync(x => x.Id == id);
        if (u == null) return NotFound();
        if (u.Id == User.UserId()) return Protected();

        var otp = PasswordService.AssignOneTimePassword(u);
        _db.Sessions.RemoveRange(_db.Sessions.Where(s => s.UserId == u.Id));
        await _db.SaveChangesAsync();
        ShowOtp(u, otp);
        return RedirectToAction(nameof(Index));
    }

    // ---------- Usuwanie ----------

    [HttpPost, Authorize(Policy = Permissions.UsersManage)]
    public async Task<IActionResult> Delete(int id)
    {
        var u = await _db.Users.FirstOrDefaultAsync(x => x.Id == id);
        if (u == null) return NotFound();
        if (IsAdminAccount(u) || u.Id == User.UserId()) return Protected();

        _db.Users.Remove(u); // sesje i historia haseł usuwane kaskadowo
        await _db.SaveChangesAsync();
        TempData["Success"] = $"Usunięto użytkownika {u.Login}.";
        return RedirectToAction(nameof(Index));
    }

    // ---------- Helpers ----------

    private static bool IsAdminAccount(AppUser u) =>
        string.Equals(u.Login, AuthConstants.AdminLogin, StringComparison.OrdinalIgnoreCase);

    private IActionResult Protected()
    {
        TempData["Error"] = "Ta operacja nie jest dozwolona dla konta ADMIN ani dla własnego konta.";
        return RedirectToAction(nameof(Index));
    }

    private void ShowOtp(AppUser u, string otp)
    {
        TempData["OtpLogin"] = u.Login;
        TempData["Otp"] = otp;
        TempData["OtpUntil"] = u.OneTimePasswordExpiresAtUtc!.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
    }
}
