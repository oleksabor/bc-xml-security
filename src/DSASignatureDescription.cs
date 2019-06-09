﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Crypto.Xml
{
    internal class DSASignatureDescription : SignatureDescription
    {
        const string HashAlgorithm = "SHA1";

        public DSASignatureDescription()
        {
            KeyAlgorithm = typeof(DSA).AssemblyQualifiedName;
            FormatterAlgorithm = typeof(DSASignatureFormatter).AssemblyQualifiedName;
            DeformatterAlgorithm = typeof(DSASignatureDeformatter).AssemblyQualifiedName;
            DigestAlgorithm = "SHA1";
        }

        public sealed override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            var item = CryptoHelpers.CreateFromName<AsymmetricSignatureDeformatter>(DeformatterAlgorithm);
            item.SetKey(key);
            item.SetHashAlgorithm(HashAlgorithm);
            return item;
        }

        public sealed override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            var item = CryptoHelpers.CreateFromName<AsymmetricSignatureFormatter>(FormatterAlgorithm);
            item.SetKey(key);
            item.SetHashAlgorithm(HashAlgorithm);
            return item;
        }

        [SuppressMessage("Microsoft.Security", "CA5350", Justification = "SHA1 needed for compat.")]
        public sealed override HashAlgorithm CreateDigest()
        {
            return SHA1.Create();
        }
    }
}