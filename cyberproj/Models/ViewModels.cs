using System.ComponentModel.DataAnnotations;

namespace cyberproj.Models;

public class LoginViewModel
{
    [Required(ErrorMessage = "Podaj login.")]
    public string Login { get; set; } = "";

    [Required(ErrorMessage = "Podaj hasło.")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = "";
}

public class ChangePasswordViewModel
{
    [DataType(DataType.Password)]
    public string? OldPassword { get; set; }

    [Required(ErrorMessage = "Podaj nowe hasło.")]
    [DataType(DataType.Password)]
    public string NewPassword { get; set; } = "";

    [Required(ErrorMessage = "Powtórz nowe hasło.")]
    [DataType(DataType.Password)]
    [Compare(nameof(NewPassword), ErrorMessage = "Hasła nie są identyczne.")]
    public string ConfirmPassword { get; set; } = "";
}

public class CreateUserViewModel
{
    [Required(ErrorMessage = "Podaj login."), StringLength(50, MinimumLength = 3)]
    [RegularExpression(@"^[A-Za-z0-9._-]+$", ErrorMessage = "Dozwolone: litery, cyfry, kropka, myślnik, podkreślenie.")]
    public string Login { get; set; } = "";

    [Required(ErrorMessage = "Podaj imię i nazwisko."), StringLength(100)]
    public string FullName { get; set; } = "";

    [Required]
    public string Role { get; set; } = Roles.Czytelnik;
}

public class EditUserViewModel
{
    public int Id { get; set; }
    public string Login { get; set; } = "";

    [Required(ErrorMessage = "Podaj imię i nazwisko."), StringLength(100)]
    public string FullName { get; set; } = "";

    [Required]
    public string Role { get; set; } = Roles.Czytelnik;
}

public class SettingsViewModel
{
    [Range(15, 128, ErrorMessage = "Minimalna długość: 15-128.")]
    [Display(Name = "Minimalna długość hasła")]
    public int MinPasswordLength { get; set; }

    [Display(Name = "Wymagaj frazy hasłowej (min. 3 słowa oddzielone spacją lub myślnikiem)")]
    public bool PassphrasePolicyEnabled { get; set; }

    [Range(0, 365, ErrorMessage = "Ważność hasła: 0-365 dni.")]
    [Display(Name = "Ważność hasła w dniach (0 = bezterminowo)")]
    public int PasswordValidityDays { get; set; }

    [Range(1, 240, ErrorMessage = "Czas bezczynności: 1-240 minut.")]
    [Display(Name = "Czas bezczynności sesji (minuty)")]
    public int SessionIdleMinutes { get; set; }
}

public class ArticleViewModel
{
    public int Id { get; set; }

    [Required(ErrorMessage = "Podaj tytuł."), StringLength(200)]
    public string Title { get; set; } = "";

    [Required(ErrorMessage = "Podaj treść."), StringLength(5000)]
    public string Content { get; set; } = "";
}
