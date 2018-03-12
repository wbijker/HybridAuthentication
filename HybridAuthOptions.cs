using System;
using Microsoft.AspNetCore.Authentication;

namespace Services.HybridAuthentication
{
    
    public class HybridAuthOptions: AuthenticationSchemeOptions
    {
        public const string DefaultScheme = "HybridAuthentication";
        public string Scheme => DefaultScheme;

        // Allow user override the default inMemory store
        public IHybridAuthStore Store { get; set; }

        #region TokenOptions
        // The HTTP header to look for the token
        public string Header { get; set; } = "Authorization";
        // Authenticatin header prefix
        public string Type { get; set; } = "Berear";
    
        #endregion

        #region CookieOptions
        public string Path { get; set; }
        // Service Set IDentitifer or also referenced as Secure Session IDentifier
        public string CookieName { get; set; } = "SSID";
        public string Domain { get; set; }
            
        #endregion
        
        // Perform a delete store operation on the store evry 5 minutes
        public TimeSpan StoreDeleteInterval = TimeSpan.FromMinutes(5);
        
        public TimeSpan Expiry { get; set; } = TimeSpan.FromDays(1);
        // public ExpiryType ExpiryType { get; set; }
        
        // Verify IP Address and UserAgent for stronger security
        public bool CheckUserAgent { get; set; } = true;
        public bool CheckIpAddress { get; set; } = true;

        // Check HTTPS flag.
        public bool OnlyHTTPS { get; set; } = false;

        // The length of the generated random string in tokens and cookie values's
        public int TokenLength { get; set; } = 128;
    }
}