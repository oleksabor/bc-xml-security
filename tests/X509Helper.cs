using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto.Xml.Tests
{
    /// <summary>
    /// configures certificate store access <seealso cref="X509Helper"/> <seealso cref="X509ThumbprintHelper"/>
    /// </summary>
    public class X509Config
    {
        /// <summary>
        /// cert store name, My by default
        /// </summary>
        public StoreName Name { get; set; } = StoreName.My;
        /// <summary>
        /// cert store location, LocalMachine by default
        /// </summary>
        public StoreLocation Location { get; set; } = StoreLocation.LocalMachine;

        /// <summary>
        /// certificate subject name
        /// </summary>
        public string CertFriendlyName { get; set; }

        /// <summary>
        /// certificate thumbprint
        /// </summary>
        public string CertThumbprint { get; set; }

        /// <summary>
        /// file path to load certificate
        /// </summary>
        public string FilePath { get; set; }

        public override string ToString()
        {
            return $"storeName:{Name} storeLocation:{Location} certName:{CertFriendlyName} certThumb:{CertThumbprint}";
        }
    }

    class X509Helper
    {

        /// <summary>
        /// loads certificate from personal (my) local machine location
        /// </summary>
        /// <param name="subject"></param>
        /// <returns></returns>
        public virtual X509Certificate2 GetCertificate(Func<X509Certificate2, bool> comparer, X509Config config)
        {
            var store = new X509Store(config.Name, config.Location);
            store.Open(OpenFlags.ReadOnly);
            var outdatedList = new Collection<string>();
            try
            {
                foreach (var cert in store.Certificates)
                    if (comparer(cert))
                        if (cert.NotAfter > DateTime.Now && cert.NotBefore < DateTime.Now)
                        {
                            //Log.Debug("certificate was found subj:{0} serial:{1}", cert.Subject, cert.GetSerialNumberString());
                            return cert;
                        }
                        else
                        {
                            var outdatedInfo = string.Format("outdated certificate '{0}' subj:{1} from:{2} to:{3}", cert.FriendlyName, cert.Subject, cert.NotBefore, cert.NotAfter);
                            outdatedList.Add(outdatedInfo);
                            //Log.Warn(outdatedInfo);
                        }
                var sb = new StringBuilder();
                sb.AppendFormat("No valid certificate was found");
                foreach (var s in outdatedList)
                {
                    sb.AppendLine();
                    sb.Append(s);
                }
                throw new KeyNotFoundException(sb.ToString());
            }
            finally
            {
                store.Close();
            }
        }
    }
}
