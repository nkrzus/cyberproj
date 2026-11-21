using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace cyberproj.Controllers;

[AllowAnonymous]
[IgnoreAntiforgeryToken]
public class ErrorController : Controller
{
    [Route("Error/{code:int}")]
    public IActionResult Index(int code)
    {
        Response.StatusCode = code;
        ViewBag.Code = code;
        return View();
    }
}
