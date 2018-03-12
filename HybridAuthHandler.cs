

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Services.HybridAuthentication
{
    public class HybridAuthenticationHandler : AuthenticationHandler<HybridAuthOptions>
    {
        private HybridAuthManager _manager;

        public HybridAuthenticationHandler(
            IOptionsMonitor<HybridAuthOptions> options, 
            HybridAuthManager manager, 
            ILoggerFactory logger,
            UrlEncoder encoder, 
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
            _manager = manager;
        }

        private string GetFirstHeader(string name, string defaultValue)
        {
            if (Request.Headers.TryGetValue(Options.TokenHeader, out var value) && value.Count == 1)
            {
                return value.ToArray()[0];
            }
            return defaultValue;
        }

        private Task<AuthenticateResult> Build(HybridAuthToken token, string message)
        {
            if (token == null)
            {
                return Task.FromResult(AuthenticateResult.Fail(message));
            }

            var principal = _manager.SignIn(token.IdentityId, false);
            var ticket = new AuthenticationTicket(principal, HybridAuthOptions.DefaultScheme);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }

        private HybridAuthToken ByCookie(string cookie)
        {
            return _manager.FindByCookie(cookie).Find(t => t.RememberMe && _manager.Validate(t));
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var token = GetFirstHeader(Options.TokenHeader, null);
            var cookie = Request.Cookies[Options.CookieName];

            // If token is absent and cookie is avaialbe
            // todo: add restriction to the page where this is allowed
            if (string.IsNullOrEmpty(token) && string.IsNullOrEmpty(cookie))
            {
                return Build(ByCookie(cookie), "Cookie invalid");
            }

            if (string.IsNullOrEmpty(token))
            {
                return Build(null, "No authorization token found");
            }
            
            if (!token.StartsWith(Options.TokenType, StringComparison.OrdinalIgnoreCase)) 
            {
                return Build(null, "Invalid token type");
            }
            
            return Build(_manager.Find(token.Substring(Options.TokenType.Length + 1)), "Token invalid");            
        }
    }
}