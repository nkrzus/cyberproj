using Microsoft.AspNetCore.Mvc;

namespace cyberproj.Controllers;

public class HomeController : Controller
{
    public IActionResult Index() => View();
}
