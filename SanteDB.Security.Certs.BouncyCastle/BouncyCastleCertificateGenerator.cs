using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using SanteDB.Core.Security.Certs;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SanteDB.Security.Certs.BouncyCastle
{
    /// <summary>
    /// 
    /// </summary>
    public class BouncyCastleCertificateGenerator : ICertificateGeneratorService
    {
       
        /// <inheritdoc/>
        public string ServiceName => "Bouncy Castle Certificate Generator";

        /// <inheritdoc/>
        public X509Certificate2 Combine(X509Certificate2 publicKey, RSAParameters privateKey)
        {
            var certificate = DotNetUtilities.FromX509Certificate(publicKey);
            var keyPair = DotNetUtilities.GetRsaKeyPair(privateKey);
            return BouncyUtils.ConvertToX509Certificate2(certificate, keyPair.Private);
        }

        /// <inheritdoc/>
        public RSAParameters CreateKeyPair(int keyLength)
        {
            var keyPair = BouncyUtils.GeneratePrivateKey(keyLength);
            return DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);
        }

        /// <inheritdoc/>
        public X509Certificate2 CreateSelfSignedCertificate(RSAParameters keyParameters, X500DistinguishedName dn, TimeSpan validityPeriod, X509KeyUsageFlags usageFlags = X509KeyUsageFlags.None)
        {
            
            var subjectDn = BouncyUtils.ConvertDN(dn);
            var keyPair = DotNetUtilities.GetRsaKeyPair(keyParameters);
            var certificate = BouncyUtils.CreateSelfSignedCertificate(subjectDn, keyPair, validityPeriod, usageFlags, false);
            return BouncyUtils.ConvertToX509Certificate2(certificate, keyPair.Private);

        }

        /// <inheritdoc/>
        public byte[] CreateSigningRequest(RSAParameters keyParameters, X500DistinguishedName dn, X509KeyUsageFlags usageFlags = X509KeyUsageFlags.None)
        {
            var subjectDn = BouncyUtils.ConvertDN(dn);
            var keyPair = DotNetUtilities.GetRsaKeyPair(keyParameters);
            var pkcs10 = new Pkcs10CertificationRequest(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, subjectDn, keyPair.Public, null, keyPair.Private);
            return pkcs10.GetDerEncoded();
        }
    }
}
