
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Caching.Memory;

namespace Services.HybridAuthentication
{
    public class HybridAuthMemoryStore : IHybridAuthStore
    {
        private const string KEYS = "KEYS";
        private MemoryCache _cache;
        
        private List<string> Keys
        {
            get
            {
                return (List<string>) _cache.Get(KEYS);
            }
        }

        private void WalkKeys(Action<HybridAuthToken> action)
        {
            foreach (string key in Keys)
            {
                if (_cache.TryGetValue(key, out HybridAuthToken item)) 
                {
                    action.Invoke(item);
                }
            }
        }

        private void RemoveKey(object key, object value, EvictionReason reason, object state)
        {
            Keys.Remove((string)key);
        }

        public HybridAuthMemoryStore()
        {   
            _cache = new MemoryCache(new MemoryCacheOptions());
            _cache.Set(KEYS, new List<string>());
        }

        public void Add(HybridAuthToken data)
        {
            using (var entry = _cache.CreateEntry(data.Token)) 
            {
                entry.Value = data;
                entry.AbsoluteExpiration = data.Expiry;
                entry.RegisterPostEvictionCallback(RemoveKey);
            }
        }

        public void DeleteExpired()
        {
            // Memory cache will take care of this
            // And PostEvictio callback wil be fired for KEYS
        }

        public List<HybridAuthToken> GetByCookie(string cookieValue)
        {
            var ret = new List<HybridAuthToken>();
            WalkKeys(item => {
                if (item.Cookie == cookieValue) 
                {
                    ret.Append(item);
                }
            });
            return ret;
        }

        public HybridAuthToken GetByToken(string token)
        {
            return _cache.Get<HybridAuthToken>(token);
        }

        public void RemoveCookie(string cookie)
        {
            WalkKeys(item => 
            {
                if (item.Cookie == cookie)
                {
                    RemoveToken(item.Token);
                }
            });
        }

        public void RemoveToken(string token)
        {
            _cache.Remove(token);
        }
    }
}
