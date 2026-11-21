using cyberproj.Data;
using cyberproj.Models;
using cyberproj.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace cyberproj.Controllers;

/// <summary>Moduł demonstracyjny do pokazania RBAC: Czytelnik czyta, Redaktor pisze, Kierownik publikuje i usuwa.</summary>
[Authorize(Policy = Permissions.ArticlesRead)]
public class ArticlesController : Controller
{
    private readonly AppDbContext _db;
    public ArticlesController(AppDbContext db) => _db = db;

    public async Task<IActionResult> Index()
    {
        var uid = User.UserId();
        bool seeAll = User.Can(Permissions.ArticlesEditAll);
        bool seeOwn = User.Can(Permissions.ArticlesCreate);

        var list = await _db.Articles.AsNoTracking()
            .Where(a => seeAll || a.IsPublished || (seeOwn && a.AuthorId == uid))
            .OrderByDescending(a => a.Id)
            .ToListAsync();
        return View(list);
    }

    [HttpGet, Authorize(Policy = Permissions.ArticlesCreate)]
    public IActionResult Create() => View("Form", new ArticleViewModel());

    [HttpPost, Authorize(Policy = Permissions.ArticlesCreate)]
    public async Task<IActionResult> Create(ArticleViewModel m)
    {
        if (!ModelState.IsValid) return View("Form", m);
        _db.Articles.Add(new Article
        {
            Title = m.Title.Trim(),
            Content = m.Content.Trim(),
            AuthorId = User.UserId(),
            AuthorLogin = User.Identity!.Name ?? "",
            CreatedAtUtc = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
        TempData["Success"] = "Artykuł zapisany jako szkic.";
        return RedirectToAction(nameof(Index));
    }

    [HttpGet]
    public async Task<IActionResult> Edit(int id)
    {
        var a = await _db.Articles.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id);
        if (a == null) return NotFound();
        if (!CanEdit(a)) return Forbid(); // kontrola na poziomie obiektu (nie tylko roli)
        return View("Form", new ArticleViewModel { Id = a.Id, Title = a.Title, Content = a.Content });
    }

    [HttpPost]
    public async Task<IActionResult> Edit(int id, ArticleViewModel m)
    {
        var a = await _db.Articles.FirstOrDefaultAsync(x => x.Id == id);
        if (a == null) return NotFound();
        if (!CanEdit(a)) return Forbid();
        m.Id = id;
        if (!ModelState.IsValid) return View("Form", m);
        a.Title = m.Title.Trim();
        a.Content = m.Content.Trim();
        await _db.SaveChangesAsync();
        TempData["Success"] = "Zapisano zmiany.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost, Authorize(Policy = Permissions.ArticlesPublish)]
    public async Task<IActionResult> Publish(int id)
    {
        var a = await _db.Articles.FirstOrDefaultAsync(x => x.Id == id);
        if (a == null) return NotFound();
        a.IsPublished = !a.IsPublished;
        await _db.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }

    [HttpPost, Authorize(Policy = Permissions.ArticlesDelete)]
    public async Task<IActionResult> Delete(int id)
    {
        var a = await _db.Articles.FirstOrDefaultAsync(x => x.Id == id);
        if (a == null) return NotFound();
        _db.Articles.Remove(a);
        await _db.SaveChangesAsync();
        TempData["Success"] = "Artykuł usunięty.";
        return RedirectToAction(nameof(Index));
    }

    private bool CanEdit(Article a) =>
        User.Can(Permissions.ArticlesEditAll) ||
        (User.Can(Permissions.ArticlesEditOwn) && a.AuthorId == User.UserId() && !a.IsPublished);
}
