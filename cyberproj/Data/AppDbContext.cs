using cyberproj.Models;
using Microsoft.EntityFrameworkCore;

namespace cyberproj.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<PasswordHistoryEntry> PasswordHistory => Set<PasswordHistoryEntry>();
    public DbSet<UserSession> Sessions => Set<UserSession>();
    public DbSet<AppSettings> Settings => Set<AppSettings>();
    public DbSet<Article> Articles => Set<Article>();

    public Task<AppSettings> GetSettingsAsync() => Settings.AsNoTracking().FirstAsync();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<AppUser>(e =>
        {
            // Login nierozróżniający wielkości liter (NOCASE) i unikalny
            e.Property(u => u.Login).HasMaxLength(50).UseCollation("NOCASE");
            e.HasIndex(u => u.Login).IsUnique();
            e.HasMany(u => u.PasswordHistory).WithOne().HasForeignKey(h => h.UserId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<UserSession>(e =>
        {
            e.HasOne(s => s.User).WithMany().HasForeignKey(s => s.UserId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}
