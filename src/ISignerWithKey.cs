using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto.Xml
{
    public interface ISignerWithKey : ISigner
    {
        AsymmetricKeyParameter Key { get; }
    }
}
