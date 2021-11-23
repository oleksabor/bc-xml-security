using System;
using System.IO;
using System.Text;
using System.Xml;
using Org.BouncyCastle.Crypto.Digests;
using Xunit;

namespace Org.BouncyCastle.Crypto.Xml.Tests
{
    public class X509SignerImplTest
    {

#if DEBUG
        /// <summary>
        /// requires ServerCert_m3 cert to be loaded into LocalMachine\Personal store.
        /// Current user must have Read permission on private key. 
        /// </summary>
        [Fact]
        public void SignWithX509NotExportableKey()
        {
            string input = "<a:Action xmlns:a='urn:foo'>http://tempuri.org/IFoo/Echo</a:Action>";

            XmlDocument doc = new XmlDocument();
            doc.LoadXml(input);
            SignedXml sxml = new SignedXml(doc);
            var config = new X509Config()
            {
                Location = System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine,
                Name = System.Security.Cryptography.X509Certificates.StoreName.My
            };
            var cert = new X509Helper().GetCertificate(_ => _.Subject.Contains("ServerCert_m3"), config);

            sxml.Signer = new X509SignerImpl(cert, new Sha256Digest()); //digest shoud be the same as used for Reference.DigestMethod


            DataObject d = new DataObject();
            //d.Data = doc.SelectNodes ("//*[local-name()='Body']/*");
            d.Data = doc.SelectNodes("//*[local-name()='Action']");
            d.Id = "_1";
            sxml.AddObject(d);
            Reference r = new Reference("#_1");
            var transform = new XmlDsigC14NTransform();
            r.AddTransform(transform);
            r.DigestMethod = SignedXml.XmlDsigSHA256Url;
            sxml.SignedInfo.AddReference(r);
            sxml.ComputeSignature();

            var sw = new MemoryStream();
            XmlWriter w = new XmlTextWriter(sw, Encoding.UTF8);
            var selement = sxml.GetXml();
            selement.WriteTo(w);
            w.Close();

            //sw.Position = 0;

            var checker = new SignedXml(doc);
            checker.LoadXml(selement); // to initialize SignatureMethod

            var bccert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(cert);

            Assert.True(checker.CheckSignature(bccert, true));

        }
#endif

        

    }
}
