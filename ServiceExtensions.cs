

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Services.HybridAuthentication
{
    public static class AuthenticationDIExtensions
    {
        public static void AddHybridAuthentication(this IServiceCollection services, Action<HybridAuthOptions> options)
        {
            services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            
            services.Configure<HybridAuthOptions>(options);
            services.AddScoped<HybridAuthManager>();

            services.AddAuthentication(configureOptions => {
                configureOptions.DefaultAuthenticateScheme = HybridAuthOptions.DefaultScheme;
                configureOptions.DefaultChallengeScheme = HybridAuthOptions.DefaultScheme;
            }).AddHybridAuth(options);
        }
    }
}


   