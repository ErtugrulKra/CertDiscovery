namespace CertificateDiscovery.Web.Controllers;

using System.Security.Claims;
using CertificateDiscovery.Infrastructure.Services;
using CertificateDiscovery.Web.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

public sealed class AccountController(UserService users) : Controller
{
    [AllowAnonymous]
    public IActionResult Login(string? returnUrl = null) => View(new LoginViewModel { ReturnUrl = returnUrl });

    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model, CancellationToken cancellationToken)
    {
        var user = await users.ValidateCredentialsAsync(model.UserName, model.Password, cancellationToken);
        if (user is null)
        {
            ModelState.AddModelError("", "Invalid user name or password.");
            return View(model);
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.UserName),
            new(ClaimTypes.Role, user.Role),
            new("DisplayName", user.DisplayName)
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

        if (!string.IsNullOrWhiteSpace(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
        {
            return Redirect(model.ReturnUrl);
        }

        return RedirectToAction("Index", "Home");
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction(nameof(Login));
    }

    [AllowAnonymous]
    public IActionResult AccessDenied() => View();
}
