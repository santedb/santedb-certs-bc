using Org.BouncyCastle.Asn1;
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
using SanteDB.Core.Security;
using SanteDB.Core.Security.Certs;
using SanteDB.Core.Security.Services;
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
        /// <summary>
        /// DI constructor
        /// </summary>
        public BouncyCastleCertificateGenerator()
        {
        }

        /// <inheritdoc/>
        public string ServiceName => "Bouncy Castle Certificate Generator";

        /// <inheritdoc/>
        public X509Certificate2 Combine(X509Certificate2 publicKey, RSAParameters privateKey, String friendlyName = null)
        {
            var certificate = DotNetUtilities.FromX509Certificate(publicKey);
            var keyPair = DotNetUtilities.GetRsaKeyPair(privateKey);
            return BouncyUtils.ConvertToX509Certificate2(friendlyName ?? certificate.SubjectDN.GetValueList(X509Name.CN).Cast<String>().First(), certificate, keyPair.Private);
        }

        /// <inheritdoc/>
        public RSAParameters CreateKeyPair(int keyLength)
        {
            var keyPair = BouncyUtils.GeneratePrivateKey(keyLength);
            return DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);
        }

        /// <inheritdoc/>
        public X509Certificate2 CreateSelfSignedCertificate(RSAParameters keyParameters, X500DistinguishedName dn, TimeSpan validityPeriod, X509KeyUsageFlags usageFlags = X509KeyUsageFlags.None, String[] extendedKeyUsages = null, String[] alternateNames = null, String friendlyName = null)
        {
            var subjectDn = BouncyUtils.ConvertDN(dn);
            var keyPair = DotNetUtilities.GetRsaKeyPair(keyParameters);
            var keyPurposes = BouncyUtils.GetKeyPurposes(extendedKeyUsages);
            var certificate = BouncyUtils.CreateSelfSignedCertificate(subjectDn, alternateNames, keyPair, validityPeriod, usageFlags, false, keyPurposes.ToArray());
            return BouncyUtils.ConvertToX509Certificate2(friendlyName ?? subjectDn.GetValueList(X509Name.CN).Cast<String>().First(), certificate, keyPair.Private);

        }

        /// <inheritdoc/>
        public byte[] CreateSigningRequest(RSAParameters keyParameters, X500DistinguishedName dn, X509KeyUsageFlags usageFlags = X509KeyUsageFlags.None, String[] extendedKeyUsages = null, String[] alternateNames = null)
        {
            var subjectDn = BouncyUtils.ConvertDN(dn);
            var keyPair = DotNetUtilities.GetRsaKeyPair(keyParameters);
            var pkcs10 = BouncyUtils.CreateSigningRequest(subjectDn, alternateNames, keyPair, usageFlags, extendedKeyUsages, false);
            var derEncoding = pkcs10.GetDerEncoded();

            using(var ms = new MemoryStream())
            {
                using(var tw = new StreamWriter(ms))
                {
                    tw.WriteLine("-----BEGIN CERTIFICATE REQUEST-----");
                    var data = Convert.ToBase64String(derEncoding);
                    tw.WriteLine(String.Join("\r\n", Enumerable.Range(0, (data.Length / 64) + 1).Select(o => data.Length < o * 64 + 64 ? data.Substring(o * 64) : data.Substring(o * 64, 64))));
                    tw.WriteLine("-----END CERTIFICATE REQUEST-----");
                }
                return ms.ToArray();
            }
        }
    }
}
