using Microsoft.AspNetCore.Authentication;

namespace Services.HybridAuthentication
{
    public class HybridAuthenticationOptions: AuthenticationSchemeOptions
    {
        public const string DefaultScheme = "HybridAuthentication";
        public string Scheme => DefaultScheme;

        
    }
}