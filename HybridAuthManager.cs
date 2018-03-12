using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Services.HybridAuthentication
{
    public class HybridAuthManager
    {
        private const string USERAGENT = "User-Agent";

        public HybridAuthOptions _options;
        private IHttpContextAccessor _context;
        // Last Datetime when we performed a delete store operation
        // StoreDeleteInterval is part op HybridAuthOptions
        private static DateTime LastDeleted = DateTime.Now;

        
        public HybridAuthManager(IOptions<HybridAuthOptions> authOptions, IHttpContextAccessor httpContextAccessor)
        {
            _context = httpContextAccessor;
            _options = authOptions.Value;
        }

        private void DeleteExpired()
        {
            // delete interval must have passed before we issue store delete
            if (DateTime.Now >= LastDeleted.Add(_options.StoreDeleteInterval))
            {
                _options.Store.DeleteExpired();
                LastDeleted = DateTime.Now;
            }
        }

        // Genearte new random token
        private string GenerateToken()
        {
            var random = new Random();
            var bytes = new byte[_options.TokenLength];
            random.NextBytes(bytes);
            // Embedded time at the begin to ensure uniqueness. 
            byte[] b = BitConverter.GetBytes(DateTime.Now.Ticks);
            Array.Copy(b, bytes, b.Length);
            return Convert.ToBase64String(bytes);
        }

        public bool Validate(HybridAuthToken token)
        {
            if (token == null)
            {
                return false;
            }
            
            return (_options.CheckIpAddress && token.IpAddress == _context.HttpContext.Connection.RemoteIpAddress.ToString())
                && (_options.CheckUserAgent && token.UserAgent == _context.HttpContext.Request.Headers[USERAGENT].ToString());
        }

        public HybridAuthToken Find(string token)
        {
            DeleteExpired();
            var data = _options.Store.GetByToken(token);
            return Validate(data) ? data : null;
        }

        public List<HybridAuthToken> FindByCookie(string cookie)
        {
            DeleteExpired();
            return _options.Store.GetByCookie(cookie);
        }

        public void Add(HybridAuthToken token)
        {
            DeleteExpired();
            _options.Store.Add(token);
        }

        public void LogOut(string token)
        {
            DeleteExpired();
            _options.Store.RemoveToken(token);
        }

        public HybridAuthToken Refresh(string token)
        {
            DeleteExpired();
            var data = _options.Store.GetByToken(token);
            if (data == null)
            {
                return null;
            }
            // At least half the time should have passed before issuing a new token
            if (DateTime.Now > data.Created.Add(_options.Expiry / 2)) 
            {
                // Delete this token
                // No need to delete cookie, because it will be override by the new one
                _options.Store.RemoveToken(token);
                // And then issue a new token
                return Login(data.IdentityId);
            }
            return null;
        }

        public ClaimsPrincipal SignIn(int id, bool httpContextSignIn = false)
        {
            var principal = new ClaimsPrincipal(new IdIdentity(id));
            if (httpContextSignIn)
            {
                _context.HttpContext.SignInAsync(_options.Scheme, principal);
            }
            return principal;
        }

        private void AddTokenToCookie(HybridAuthToken token)
        {
            // If there is a cookie add to current cookie
            string cookieValue = _context.HttpContext.Request.Cookies[_options.CookieName];
            if (!String.IsNullOrEmpty(cookieValue))
            {
                token.Cookie = cookieValue;
                return;
            }

            // We need to create a new cookie
            string newCookie = GenerateToken();

            // If not create a cookie
            CookieOptions options = new CookieOptions {
                Domain = _options.Domain,
                Expires = token.Expiry,
                Path = _options.Path,
                HttpOnly = true,
                Secure = _options.OnlyHTTPS,
                SameSite = SameSiteMode.None
            };
            // _context.HttpContext.Response.Cookies.
            _context.HttpContext.Response.Cookies.Append(_options.CookieName, newCookie, options);
            token.Cookie = newCookie;
        }

        public HybridAuthToken Login(int id)
        {
            // 1. Generate new token 
            var ret = new HybridAuthToken();
            ret.IdentityId = id;
            ret.Token = GenerateToken();
            ret.UserAgent = _context.HttpContext.Request.Headers[USERAGENT];
            ret.IpAddress = _context.HttpContext.Connection.RemoteIpAddress.ToString();
            ret.Created = DateTime.Now;
            ret.Expiry = DateTime.Now.Add(_options.Expiry);
            // 2. Set cookie
            AddTokenToCookie(ret);

            // 3. Add to store
            Add(ret);

            // 3. Set user as logged in
            SignIn(id, true);
            return ret;
        }
    }
}