using System.Security.Claims;

namespace Services.HybridAuthentication
{
    // Identity with strongly typed id
    // No need to cast / ship everything in claims
    public class IdIdentity: ClaimsIdentity
    {
        public int Id { get; set; }

        // Simply constructing ClaimsIdentity does not set Authenticated to true
        // https://leastprivilege.com/2012/09/24/claimsidentity-isauthenticated-and-authenticationtype-in-net-4-5/
        public IdIdentity(int id): base(null, "IdIdentity") 
        {
            Id = id;
        }
    }
}