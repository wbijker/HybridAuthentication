using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace Services.HybridAuthentication
{
    public interface IPopulater<out T>
    {
        T Populate(int id);
    }
}