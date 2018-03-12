

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
    public class HybridAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private HybridAuthManager _manager;
        private HybridAuthOptions _authOptions;

        public HybridAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            IOptions<HybridAuthOptions> authOptions,
            HybridAuthManager manager, 
            ILoggerFactory logger,
            UrlEncoder encoder, 
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
            _manager = manager;
            _authOptions = authOptions.Value;
        }

        private string GetFirstHeader(string name, string defaultValue)
        {
            if (Request.Headers.TryGetValue(_authOptions.TokenHeader, out var value) && value.Count == 1)
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
            var token = GetFirstHeader(_authOptions.TokenHeader, null);
            var cookie = Request.Cookies[_authOptions.CookieName];

            // If token is absent and cookie is avaialbe
            // todo: add restriction to the page where this is allowed
            if (string.IsNullOrEmpty(token) && !string.IsNullOrEmpty(cookie))
            {
                return Build(ByCookie(cookie), "Cookie invalid");
            }

            if (string.IsNullOrEmpty(token))
            {
                return Build(null, "No authorization token found");
            }
            
            if (!token.StartsWith(_authOptions.TokenType, StringComparison.OrdinalIgnoreCase)) 
            {
                return Build(null, "Invalid token type");
            }
            
            return Build(_manager.Find(token.Substring(_authOptions.TokenType.Length + 1)), "Token invalid");            
        }
    }
}