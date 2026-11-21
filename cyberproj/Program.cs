using cyberproj.Data;
using cyberproj.Security;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(o =>
    o.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=app.db"));

// CSRF: każdy POST/PUT/DELETE wymaga tokenu antyforgery
builder.Services.AddControllersWithViews(o => o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/Account/Login";
        o.Cookie.Name = "cyberproj.auth";
        o.Cookie.HttpOnly = true;
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        o.Cookie.SameSite = SameSiteMode.Strict;
        o.ExpireTimeSpan = TimeSpan.FromHours(12);   // górny limit; faktyczną bezczynność pilnuje SessionMiddleware
        o.SlidingExpiration = false;
        // Brak uprawnień => prawdziwy status 403 (strona błędu renderowana przez UseStatusCodePagesWithReExecute)
        o.Events.OnRedirectToAccessDenied = ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorization(o =>
{
    // Domyślnie wszystko wymaga zalogowania (poza [AllowAnonymous])
    o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();

    // Jedna polityka na każde uprawnienie RBAC
    foreach (var permission in Permissions.All)
    {
        var p = permission;
        o.AddPolicy(p, policy => policy
            .RequireAuthenticatedUser()
            .RequireAssertion(ctx => ctx.User.Can(p)));
    }
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    DbSeeder.Seed(scope.ServiceProvider.GetRequiredService<AppDbContext>(), app.Environment);
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error/500");
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/Error/{0}");
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseMiddleware<SessionMiddleware>();
app.UseAuthorization();

app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
