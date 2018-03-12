using System;

namespace Services.HybridAuthentication
{
    public class HybridAuthToken
    {
        // Cookie's value
        public string Cookie { get; set; }
        // Token's value
        public string Token { get; set; }
        // AccountId associated with the token
        public int IdentityId { get; set; }
        public bool RememberMe { get; set; }
        public string UserAgent { get; set; }
        public string IpAddress { get; set; }
        public DateTime Expiry { get; set; }
        public DateTime Created { get; set; }
    }
}
