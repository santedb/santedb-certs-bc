using SanteDB.Core.Security.Services;
using System.Security.Principal;

namespace SanteDB.Security.Certs.BouncyCastle.Test
{
    internal class TestPolicyEnforcementService : IPolicyEnforcementService
    {
        public string ServiceName => "Test PEP - IF YOU SEE THIS IN PRODUCTION CHANGE IT!";

        public void Demand(string policyId)
        {
        }

        public void Demand(string policyId, IPrincipal principal)
        {
        }

        public bool SoftDemand(string policyId, IPrincipal principal) => true;
    }
}