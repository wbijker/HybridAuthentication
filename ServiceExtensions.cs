

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
        public static void AddHybridAuthentication<T, P>(this IServiceCollection services, Action<HybridAuthOptions> options) 
            where P: class, IPopulater<T> where T: class, new()
        {
            // Make sure HttpContextAccessor is registered
            services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();   
            // Register populator class to populate a new T from id
            services.AddScoped<IPopulater<T>, P>();
            
            services.AddTransient<T>((IServiceProvider prov) => {
                // Ger various servies
                var contextAccesor = prov.GetService<IHttpContextAccessor>();
                var identity = contextAccesor.HttpContext.User?.Identity ?? null;
                // HyypContext.User should be populated by the HybridAuthHandler
                if (identity != null && identity.IsAuthenticated && identity is IdIdentity)
                {
                    // Get the populater interface 
                    var populator = prov.GetService<IPopulater<T>>();
                    return populator.Populate((identity as IdIdentity).Id);
                } 
                // Could not return null
                // It will result in unable to resolve service for .. while activating ...
                return new T();
            });

            
            services.Configure<HybridAuthOptions>(options);
            services.AddScoped<HybridAuthManager>();

            services.AddAuthentication(configureOptions => {
                configureOptions.DefaultAuthenticateScheme = HybridAuthOptions.DefaultScheme;
                configureOptions.DefaultChallengeScheme = HybridAuthOptions.DefaultScheme;
            }).AddHybridAuth(options);
        }
    }
}


   