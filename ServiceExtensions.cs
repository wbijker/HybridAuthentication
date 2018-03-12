

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

        public class HybridAuthenticationBuilder<T>
        {
            private IServiceCollection _service;
            public HybridAuthenticationBuilder(IServiceCollection service)
            {
                _service = service;
            }

            public HybridAuthenticationBuilder<T> RegisterPopulator<P>() where P: class, IPopulater<T>
            {
                _service.AddScoped<IPopulater<T>, P>();
                return this;
            }

            public HybridAuthenticationBuilder<T> RegisterStore<P>() where P:class, IHybridAuthStore
            {
                _service.AddScoped<IHybridAuthStore, P>();
                return this;
            }
        }

        public static HybridAuthenticationBuilder<T> AddHybridAuthentication<T>(this IServiceCollection services, Action<HybridAuthOptions> options) where T: class, new()
        {
            // Make sure HttpContextAccessor is registered
            services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();   
            
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
            }).AddHybridAuth();

            return new HybridAuthenticationBuilder<T>(services);
        }
    }
}


   