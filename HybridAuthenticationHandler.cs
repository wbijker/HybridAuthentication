

using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Services.HybridAuthentication
{
    public class HybridAuthenticationHandler : AuthenticationHandler<HybridAuthenticationOptions>
    {
        protected HybridAuthenticationHandler(IOptionsMonitor<HybridAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // Create new authenticated user
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(new IdIdentity(11)), Options.Scheme);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }
}