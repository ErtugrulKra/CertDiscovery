namespace CertificateDiscovery.Web.Infrastructure;

using CertificateDiscovery.Application.Options;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class WorkerApiKeyFilterAttribute : Attribute, IAsyncAuthorizationFilter
{
    public Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<CertificateDiscoveryOptions>>().Value;
        var provided = context.HttpContext.Request.Headers["X-Worker-Api-Key"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(options.WorkerApiKey) || provided != options.WorkerApiKey)
        {
            context.Result = new UnauthorizedObjectResult(new ProblemDetails { Title = "Invalid worker API key", Status = StatusCodes.Status401Unauthorized });
        }

        return Task.CompletedTask;
    }
}
