namespace CertificateDiscovery.Web.Models;

public sealed class LoginViewModel
{
    public string UserName { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string? ReturnUrl { get; set; }
}

public sealed class CreateUserViewModel
{
    public string UserName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Role { get; set; } = "Read";
    public string Password { get; set; } = string.Empty;
}

public sealed class UserProfileViewModel
{
    public string UserName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public string CurrentPassword { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
    public string ConfirmPassword { get; set; } = string.Empty;
}
