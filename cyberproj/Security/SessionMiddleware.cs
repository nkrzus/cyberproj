using System.Security.Claims;
using cyberproj.Data;
using cyberproj.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

namespace cyberproj.Security;

public static class SessionHelper
{
    public static ClaimsPrincipal BuildPrincipal(AppUser u, string sessionId)
    {
        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, u.Id.ToString()),
            new Claim(ClaimTypes.Name, u.Login),
            new Claim(ClaimTypes.Role, u.Role),
            new Claim(AuthConstants.SessionIdClaim, sessionId),
        }, CookieAuthenticationDefaults.AuthenticationScheme);
        return new ClaimsPrincipal(identity);
    }
}

/// <summary>
/// Sesja po stronie serwera: sprawdza, czy sesja istnieje, czy konto nie jest zablokowane i czy nie minął czas
/// bezczynności (ustawiany przez admina). Dane użytkownika (rola) są odświeżane z bazy przy każdym żądaniu,
/// więc zmiana roli / blokada działają natychmiast. Wymusza też zmianę hasła przy pierwszym logowaniu.
/// </summary>
public class SessionMiddleware
{
    private readonly RequestDelegate _next;
    public SessionMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx, AppDbContext db)
    {
        // Strony po zalogowaniu nie powinny być cache'owane (przycisk "Wstecz" po wylogowaniu)
        ctx.Response.Headers["Cache-Control"] = "no-store";

        if (ctx.User.Identity?.IsAuthenticated == true)
        {
            var sid = ctx.User.FindFirst(AuthConstants.SessionIdClaim)?.Value;
            var session = sid == null ? null : await db.Sessions.Include(s => s.User).FirstOrDefaultAsync(s => s.Id == sid);
            var settings = await db.GetSettingsAsync();
            var now = DateTime.UtcNow;

            bool idle = session != null && now - session.LastActivityUtc > TimeSpan.FromMinutes(settings.SessionIdleMinutes);

            if (session == null || session.User.IsBlocked || idle)
            {
                if (session != null)
                {
                    db.Sessions.Remove(session);
                    await db.SaveChangesAsync();
                }
                await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                ctx.Response.Redirect("/Account/Login?reason=" + (idle ? "timeout" : "expired"));
                return;
            }

            session.LastActivityUtc = now;
            await db.SaveChangesAsync();
            ctx.User = SessionHelper.BuildPrincipal(session.User, session.Id);

            if (session.User.MustChangePassword && !IsAllowedWhenForcedChange(ctx.Request.Path))
            {
                ctx.Response.Redirect("/Account/FirstLogin");
                return;
            }
        }

        await _next(ctx);
    }

    private static bool IsAllowedWhenForcedChange(PathString p) =>
        p.StartsWithSegments("/Account/FirstLogin") ||
        p.StartsWithSegments("/Account/Logout") ||
        p.StartsWithSegments("/Error");
}
