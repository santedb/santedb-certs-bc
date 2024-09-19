/*
 * Copyright (C) 2021 - 2024, SanteSuite Inc. and the SanteSuite Contributors (See NOTICE.md for full copyright notices)
 * Copyright (C) 2019 - 2021, Fyfe Software Inc. and the SanteSuite Contributors
 * Portions Copyright (C) 2015-2018 Mohawk College of Applied Arts and Technology
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using SanteDB.Core.Security.Certs;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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

            using (var ms = new MemoryStream())
            {
                using (var tw = new StreamWriter(ms))
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
