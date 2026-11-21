using cyberproj.Data;
using cyberproj.Models;
using cyberproj.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace cyberproj.Controllers;

[Authorize(Policy = Permissions.SettingsManage)]
public class SettingsController : Controller
{
    private readonly AppDbContext _db;
    public SettingsController(AppDbContext db) => _db = db;

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var s = await _db.GetSettingsAsync();
        return View(new SettingsViewModel
        {
            MinPasswordLength = s.MinPasswordLength,
            PassphrasePolicyEnabled = s.PassphrasePolicyEnabled,
            PasswordValidityDays = s.PasswordValidityDays,
            SessionIdleMinutes = s.SessionIdleMinutes
        });
    }

    [HttpPost]
    public async Task<IActionResult> Index(SettingsViewModel m)
    {
        if (!ModelState.IsValid) return View(m);
        var s = await _db.Settings.FirstAsync();
        s.MinPasswordLength = m.MinPasswordLength;
        s.PassphrasePolicyEnabled = m.PassphrasePolicyEnabled;
        s.PasswordValidityDays = m.PasswordValidityDays;
        s.SessionIdleMinutes = m.SessionIdleMinutes;
        await _db.SaveChangesAsync();
        TempData["Success"] = "Ustawienia zapisane.";
        return RedirectToAction(nameof(Index));
    }
}
