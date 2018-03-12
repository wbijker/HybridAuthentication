using System;
using Microsoft.AspNetCore.Authentication;

namespace Services.HybridAuthentication
{
    public static class AuthenticationBuilderExtensions
    {
        public static AuthenticationBuilder AddHybridAuth(this AuthenticationBuilder builder, Action<HybridAuthOptions> configureOptions)
        {
            // Add  hybrid authentication scheme with custom options and custom handler
            return builder.AddScheme<HybridAuthOptions, HybridAuthenticationHandler>(HybridAuthOptions.DefaultScheme, configureOptions);
        }
    }
}