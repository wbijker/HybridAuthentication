

using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Services.HybridAuthentication
{
    public class HybridAuthenticationHandler : AuthenticationHandler<HybridAuthOptions>
    {
        private HybridAuthManager _manager;

        protected HybridAuthenticationHandler(IOptionsMonitor<HybridAuthOptions> options, HybridAuthManager manager, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
            _manager = manager;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var principal = _manager.SignIn(11, false);
            var ticket = new AuthenticationTicket(principal, Options.Scheme);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }
}