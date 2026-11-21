using System.Security.Claims;
using cyberproj.Models;

namespace cyberproj.Security;

public static class AuthConstants
{
    public const string AdminLogin = "ADMIN";
    public const string SessionIdClaim = "sid";
}

/// <summary>RBAC: uprawnienia przypisane rolom (zasada najmniejszych uprawnień).</summary>
public static class Permissions
{
    public const string UsersView = "users.view";
    public const string UsersManage = "users.manage";
    public const string SettingsManage = "settings.manage";
    public const string ArticlesRead = "articles.read";
    public const string ArticlesCreate = "articles.create";
    public const string ArticlesEditOwn = "articles.edit.own";
    public const string ArticlesEditAll = "articles.edit.all";
    public const string ArticlesPublish = "articles.publish";
    public const string ArticlesDelete = "articles.delete";

    public static readonly string[] All =
    {
        UsersView, UsersManage, SettingsManage, ArticlesRead, ArticlesCreate,
        ArticlesEditOwn, ArticlesEditAll, ArticlesPublish, ArticlesDelete
    };

    public static readonly Dictionary<string, string> Descriptions = new()
    {
        [UsersView] = "podgląd listy użytkowników",
        [UsersManage] = "dodawanie, edycja, blokowanie, usuwanie użytkowników i reset haseł",
        [SettingsManage] = "polityka haseł, ważność hasła, czas bezczynności sesji",
        [ArticlesRead] = "czytanie artykułów (opublikowanych; Redaktor także własnych szkiców)",
        [ArticlesCreate] = "tworzenie artykułów",
        [ArticlesEditOwn] = "edycja własnych, nieopublikowanych artykułów",
        [ArticlesEditAll] = "edycja wszystkich artykułów",
        [ArticlesPublish] = "publikowanie artykułów",
        [ArticlesDelete] = "usuwanie artykułów",
    };

    public static readonly IReadOnlyDictionary<string, HashSet<string>> Matrix =
        new Dictionary<string, HashSet<string>>
        {
            [Roles.Administrator] = new() { UsersView, UsersManage, SettingsManage },
            [Roles.Kierownik] = new() { UsersView, ArticlesRead, ArticlesCreate, ArticlesEditAll, ArticlesPublish, ArticlesDelete },
            [Roles.Redaktor] = new() { ArticlesRead, ArticlesCreate, ArticlesEditOwn },
            [Roles.Czytelnik] = new() { ArticlesRead },
        };

    public static bool Has(string? role, string permission) =>
        role != null && Matrix.TryGetValue(role, out var set) && set.Contains(permission);

    public static IEnumerable<string> ForRole(string? role) =>
        All.Where(p => Has(role, p));
}

public static class UserExtensions
{
    public static string? RoleName(this ClaimsPrincipal u) => u.FindFirst(ClaimTypes.Role)?.Value;
    public static bool Can(this ClaimsPrincipal u, string permission) => Permissions.Has(u.RoleName(), permission);
    public static int UserId(this ClaimsPrincipal u) => int.Parse(u.FindFirst(ClaimTypes.NameIdentifier)!.Value);
}
