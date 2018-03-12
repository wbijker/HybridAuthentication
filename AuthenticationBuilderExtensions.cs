using System;
using Microsoft.AspNetCore.Authentication;

namespace Services.HybridAuthentication
{


    public static class AuthenticationBuilderExtensions
    {
        public static AuthenticationBuilder AddCustomAuth(this AuthenticationBuilder builder, Action<HybridAuthenticationOptions> configureOptions)
        {
            // Add  hybrid authentication scheme with custom options and custom handler
            return builder.AddScheme<HybridAuthenticationOptions, HybridAuthenticationHandler>(HybridAuthenticationOptions.DefaultScheme, configureOptions);
        }
    }
}