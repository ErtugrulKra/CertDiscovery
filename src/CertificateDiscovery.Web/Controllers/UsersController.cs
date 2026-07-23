namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Infrastructure.Services;
using CertificateDiscovery.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize(Roles = "Admin")]
public sealed class UsersController(UserService users) : Controller
{
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
        => View(await users.ListAsync(cancellationToken));

    public IActionResult Create() => View(new CreateUserViewModel());

    [HttpPost]
    public async Task<IActionResult> Create(CreateUserViewModel model, CancellationToken cancellationToken)
    {
        try
        {
            await users.CreateAsync(model.UserName, model.DisplayName, model.Role, model.Password, cancellationToken);
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(model);
        }
    }

    [HttpPost]
    public async Task<IActionResult> Toggle(Guid id, CancellationToken cancellationToken)
    {
        await users.ToggleAsync(id, cancellationToken);
        return RedirectToAction(nameof(Index));
    }
}
