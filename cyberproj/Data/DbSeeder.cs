using cyberproj.Models;
using cyberproj.Security;

namespace cyberproj.Data;

public static class DbSeeder
{
    public static void Seed(AppDbContext db, IHostEnvironment env)
    {
        db.Database.EnsureCreated();

        if (!db.Settings.Any())
            db.Settings.Add(new AppSettings());

        if (!db.Users.Any())
        {
            var created = new List<(string Login, string Role, string Otp)>();

            void Add(string login, string fullName, string role)
            {
                var u = new AppUser { Login = login, FullName = fullName, Role = role, CreatedAtUtc = DateTime.UtcNow };
                var otp = PasswordService.AssignOneTimePassword(u);
                db.Users.Add(u);
                created.Add((login, role, otp));
            }

            // Stałe konto administratora + 7 użytkowników testowych (wariant 6)
            Add(AuthConstants.AdminLogin, "Administrator systemu", Roles.Administrator);
            Add("anna.kowalska", "Anna Kowalska", Roles.Kierownik);
            Add("jan.nowak", "Jan Nowak", Roles.Kierownik);
            Add("ewa.wisniewska", "Ewa Wiśniewska", Roles.Redaktor);
            Add("piotr.zielinski", "Piotr Zieliński", Roles.Redaktor);
            Add("maria.dabrowska", "Maria Dąbrowska", Roles.Czytelnik);
            Add("katarzyna.wojcik", "Katarzyna Wójcik", Roles.Czytelnik);

            db.SaveChanges();

            // Hasła jednorazowe są wyświetlane tylko RAZ - w konsoli (i w pliku, wyłącznie w trybie Development).
            var lines = new List<string>
            {
                "=== HASŁA JEDNORAZOWE (ważne 48 h, wymuszą zmianę przy pierwszym logowaniu) ==="
            };
            lines.AddRange(created.Select(c => $"{c.Login,-22} {c.Role,-12} {c.Otp}"));
            foreach (var l in lines) Console.WriteLine(l);

            if (env.IsDevelopment())
                File.WriteAllLines(Path.Combine(env.ContentRootPath, "haslo-jednorazowe.txt"), lines);
        }

        db.SaveChanges();
    }
}
