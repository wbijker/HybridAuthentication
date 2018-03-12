using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace Services.HybridAuthentication
{
    // Store to persist cookie / token data
    public interface IHybridAuthStore
    {
        HybridAuthToken GetByToken(string token);
        List<HybridAuthToken> GetByCookie(string cookieValue);
        void Add(HybridAuthToken data);
        void RemoveToken(string token);
        void RemoveCookie(string cookie);
        void DeleteExpired();
    }
}