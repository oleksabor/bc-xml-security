using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class X509SignerImpl : ISignerWithKey
    {
        private readonly X509Certificate2 _cert;
        private readonly IDigest _digest;

        public X509SignerImpl(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
            :this(cert, new Sha256Digest())
        { }

        public X509SignerImpl(System.Security.Cryptography.X509Certificates.X509Certificate2 cert, IDigest digest)
        {
            _cert = cert;
            _digest = digest;
        }



        public string AlgorithmName => _cert.PublicKey.Key.SignatureAlgorithm;

        public AsymmetricKeyParameter Key => Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(_cert).GetPublicKey();

        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            _digest.BlockUpdate(input, inOff, length);
        }
        public byte[] GenerateSignature()
        {
            var key = System.Security.Cryptography.X509Certificates.RSACertificateExtensions.GetRSAPrivateKey(_cert);
            byte[] hash = new byte[_digest.GetDigestSize()];
            _digest.DoFinal(hash, 0);
            return key.SignHash(hash, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        }

        public void Init(bool forSigning, ICipherParameters parameters)
        {
            // doing nothing
        }
        public void Reset()
        {
            _digest.Reset();
        }
        public void Update(byte input)
        {
            _digest.Update(input);
        }
        public bool VerifySignature(byte[] signature)
        {
            throw new NotImplementedException();
        }
    }
}
