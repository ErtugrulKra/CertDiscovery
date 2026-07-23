namespace CertificateDiscovery.Web.Controllers;

using System.Security.Claims;
using CertificateDiscovery.Infrastructure.Services;
using CertificateDiscovery.Web.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize]
public sealed class UserProfileController(UserService users) : Controller
{
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var user = await users.GetAsync(CurrentUserId(), cancellationToken);
        return user is null ? NotFound() : View(new UserProfileViewModel
        {
            UserName = user.UserName,
            DisplayName = user.DisplayName,
            Role = user.Role
        });
    }

    [HttpPost]
    public async Task<IActionResult> UpdateProfile(UserProfileViewModel model, CancellationToken cancellationToken)
    {
        try
        {
            var user = await users.UpdateProfileAsync(CurrentUserId(), model.DisplayName, cancellationToken);
            await RefreshSignInAsync(user.UserName, user.DisplayName, user.Role);
            TempData["ProfileMessage"] = "Profile was updated.";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            TempData["ProfileError"] = ex.Message;
        }

        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> ChangePassword(UserProfileViewModel model, CancellationToken cancellationToken)
    {
        try
        {
            await users.ChangePasswordAsync(CurrentUserId(), model.CurrentPassword, model.NewPassword, model.ConfirmPassword, cancellationToken);
            TempData["ProfileMessage"] = "Password was changed.";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            TempData["ProfileError"] = ex.Message;
        }

        return RedirectToAction(nameof(Index));
    }

    private Guid CurrentUserId()
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(value, out var id) ? id : throw new InvalidOperationException("Current user id is invalid.");
    }

    private async Task RefreshSignInAsync(string userName, string displayName, string role)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, CurrentUserId().ToString()),
            new(ClaimTypes.Name, userName),
            new(ClaimTypes.Role, role),
            new("DisplayName", displayName)
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
    }
}
