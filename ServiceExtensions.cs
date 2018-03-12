

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Services.HybridAuthentication
{
    public static class AuthenticationDIExtensions
    {
        public static void AddHybridAuthentication<T>(this IServiceCollection services)
        {
            services.Configure<HybridAuthOptions>(config => {
                config.CookieName = "dsafsa";
            });

            services.AddScoped<HybridAuthManager>();
            services.AddAuthentication().AddHybridAuth(options => {
                
            });
        }
    }
}


   