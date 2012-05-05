using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Chq.OAuth
{
    public enum OAuthProblem { Unauthorised };

    public class OAuthException : Exception
    {
        public OAuthProblem Problem { get; set; }
    }
}
