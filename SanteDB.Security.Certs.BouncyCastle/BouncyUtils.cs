/*
 * Copyright (C) 2021 - 2023, SanteSuite Inc. and the SanteSuite Contributors (See NOTICE.md for full copyright notices)
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
 * User: fyfej
 * Date: 2023-3-10
 */
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using SanteDB.Core.i18n;
using SanteDB.Security.Certs.BouncyCastle.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

#pragma warning disable CS0618

namespace SanteDB.Security.Certs.BouncyCastle
{
    /// <summary>
    /// Bouncy castle utilities
    /// </summary>
    internal static class BouncyUtils
    {
        /// <summary>
        /// The signature algorithm used by this generator
        /// </summary>
        public const string SIGNATURE_ALGORITHM = "SHA256WithRSA";

        internal static Org.BouncyCastle.X509.X509Certificate CreateSelfSignedCertificate(X509Name subjectDn, String[] alternateNames, AsymmetricCipherKeyPair keyPair, TimeSpan validityPeriod, X509KeyUsageFlags usageFlags, bool isCaCertificate, KeyPurposeID[] extendedKeyPurposes)
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var certificateGenerator = new X509V3CertificateGenerator();
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetSignatureAlgorithm(SIGNATURE_ALGORITHM);
            certificateGenerator.SetSubjectDN(subjectDn);
            certificateGenerator.SetIssuerDN(subjectDn);
            certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
            certificateGenerator.SetNotAfter(DateTime.UtcNow.Add(validityPeriod));
            certificateGenerator.SetPublicKey(keyPair.Public);
            var uses = ConvertUsages(usageFlags);
            if(uses > 0)
            {
                certificateGenerator.AddExtension(X509Extensions.KeyUsage.Id, false, new KeyUsage(uses));
            }
            if (extendedKeyPurposes.Any())
            {
                certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false, new ExtendedKeyUsage(extendedKeyPurposes));
            }
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false, new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public), new GeneralNames(new GeneralName(subjectDn)), serialNumber));
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, false, new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public)));
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, false, new BasicConstraints(isCaCertificate));

            if(alternateNames?.Any() == true)
            {
                certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName.Id, false, new DerSequence(alternateNames.Select(o=>new GeneralName(IPAddress.TryParse(o, out _) ? GeneralName.IPAddress : GeneralName.DnsName, o)).ToArray()));
            }
            return certificateGenerator.Generate(keyPair.Private, random);
        }

        /// <summary>
        /// Create a signing request
        /// </summary>
        internal static Pkcs10CertificationRequest CreateSigningRequest(X509Name subjectDn, String[] alternateNames, AsymmetricCipherKeyPair keyPair, X509KeyUsageFlags usageFlags, string[] extendedKeyUsages, bool isCa)
        {
            var extensions = new Dictionary<DerObjectIdentifier, Org.BouncyCastle.Asn1.X509.X509Extension>();
            extensions.Add(X509Extensions.ExtendedKeyUsage, new Org.BouncyCastle.Asn1.X509.X509Extension(false, new DerOctetString(new ExtendedKeyUsage(BouncyUtils.GetKeyPurposes(extendedKeyUsages).ToArray()))));
            extensions.Add(X509Extensions.KeyUsage, new Org.BouncyCastle.Asn1.X509.X509Extension(false, new DerOctetString( new KeyUsage(BouncyUtils.ConvertUsages(usageFlags)))));
            extensions.Add(X509Extensions.BasicConstraints, new Org.BouncyCastle.Asn1.X509.X509Extension(true, new DerOctetString(new BasicConstraints(isCa))));
            if (alternateNames?.Any() == true)
            {
                extensions.Add(X509Extensions.SubjectAlternativeName, new Org.BouncyCastle.Asn1.X509.X509Extension(false, new DerOctetString(new DerSequence(alternateNames.Select(o => new GeneralName(IPAddress.TryParse(o, out _) ? GeneralName.IPAddress : GeneralName.DnsName, o)).ToArray()))));
            }

            var derSet = new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(new X509Extensions(extensions))));
            return new Pkcs10CertificationRequest(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, subjectDn, keyPair.Public, derSet, keyPair.Private);
        }

        /// <summary>
        /// Sign a certificate request 
        /// </summary>
        internal static Org.BouncyCastle.X509.X509Certificate SignCertificateRequest(Pkcs10CertificationRequest csrRequest, TimeSpan validityPeriod, AsymmetricCipherKeyPair issuerKeyPair, Org.BouncyCastle.X509.X509Certificate issuerCertificate, BouncyCastleCertificateSignPurpose issuerUses)
        {
            if(csrRequest.Verify())
            {
                throw new InvalidOperationException(ErrorMessages.CERTIFICATE_REQ_NOT_VALID);
            }

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var certificateGenerator = new X509V3CertificateGenerator();
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetSignatureAlgorithm(csrRequest.SignatureAlgorithm.Algorithm.Id);
            certificateGenerator.SetIssuerDN(issuerCertificate.SubjectDN);
            certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
            certificateGenerator.SetNotAfter(DateTime.UtcNow.Add(validityPeriod));

            var certInfo = csrRequest.GetCertificationRequestInfo();
            certificateGenerator.SetSubjectDN(certInfo.Subject);
            certificateGenerator.SetPublicKey(csrRequest.GetPublicKey());

            // Validate that this cert can be used to sign the other cert
            var attributes = csrRequest.GetCertificationRequestInfo().Attributes;
            bool canSign = true;
            if (attributes != null)
            {
                foreach(var att in attributes)
                {
                    var attr = AttributePkcs.GetInstance(att);
                    if (attr.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
                    {
                        var extension = X509Extensions.GetInstance(attr.AttrValues[0]);
                        foreach (DerObjectIdentifier oid in extension.ExtensionOids)
                        {
                            var ext = extension.GetExtension(oid);
                            var value = ext.GetParsedValue();
                            certificateGenerator.AddExtension(oid, ext.IsCritical, value);

                            if(oid.Equals(X509Extensions.BasicConstraints) && value is BasicConstraints bc)
                            {
                                canSign &= bc.IsCA() && issuerUses.HasFlag(BouncyCastleCertificateSignPurpose.CertificateAuthority) || !bc.IsCA();
                            }
                            else if(oid.Equals(X509Extensions.ExtendedKeyUsage) && value is ExtendedKeyUsage eku)
                            {
                                foreach(KeyPurposeID kpi in eku.GetAllUsages())
                                {
                                    canSign &= (!kpi.Equals(KeyPurposeID.IdKPServerAuth) ^ issuerUses.HasFlag(BouncyCastleCertificateSignPurpose.ServerAuth)) &&
                                        (!kpi.Equals(KeyPurposeID.IdKPClientAuth) ^ issuerUses.HasFlag(BouncyCastleCertificateSignPurpose.ClientAuth)) &&
                                        (!kpi.Equals(KeyPurposeID.IdKPCodeSigning) ^ issuerUses.HasFlag(BouncyCastleCertificateSignPurpose.CodeSigning)) &&
                                        (!kpi.Equals(KeyPurposeID.IdKPSmartCardLogon) ^ issuerUses.HasFlag(BouncyCastleCertificateSignPurpose.SmartCards)) &&
                                        !kpi.Equals(KeyPurposeID.IdKPEmailProtection) && !kpi.Equals(KeyPurposeID.IdKPIpsecEndSystem) &&
                                        !kpi.Equals(KeyPurposeID.IdKPIpsecTunnel) && !kpi.Equals(KeyPurposeID.IdKPIpsecUser) &&
                                        !kpi.Equals(KeyPurposeID.IdKPTimeStamping) &&
                                        !kpi.Equals(KeyPurposeID.IdKPMacAddress) && !kpi.Equals(KeyPurposeID.IdKPOcspSigning);
                                }
                            }
                        }
                    }
                }
            }

            if(!canSign)
            {
                throw new InvalidOperationException(ErrorMessages.CERTIFICATE_REQ_CANT_SIGN);
            }
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false, new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerKeyPair.Public), new GeneralNames(new GeneralName(issuerCertificate.SubjectDN)), issuerCertificate.SerialNumber));
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, false, new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(csrRequest.GetPublicKey())));

            return certificateGenerator.Generate(issuerKeyPair.Private);

        }

        /// <summary>
        /// Read the certificate signing request
        /// </summary>
        /// <param name="request">The request in DER or PEM format</param>
        internal static Pkcs10CertificationRequest ReadSigningRequest(byte[] request)
        {
            if (request[0] == (byte)'-') // PEM
            {
                using(var ms = new MemoryStream(request))
                {
                    using(var sr = new StreamReader(ms))
                    {
                        var reader = new PemReader(sr);
                        return (Pkcs10CertificationRequest)reader.ReadObject();
                    }
                }
            }
            else // DER
            {
                return new Pkcs10CertificationRequest(request);
            }
        }

        /// <summary>
        /// Get key purpose identifiers
        /// </summary>
        internal static IEnumerable<KeyPurposeID> GetKeyPurposes(String[] extendedKeyUsages)
        {
            if(extendedKeyUsages == null)
            {
                yield break;
            }

            var dictPurpose = typeof(KeyPurposeID).GetFields(System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Public)
                .Select(f => f.GetValue(null))
                .OfType<KeyPurposeID>()
                .ToDictionary(o => o.Id, o => o);

            foreach(var itm in extendedKeyUsages)
            {
                if(dictPurpose.TryGetValue(itm, out var k))
                {
                    yield return k;
                }
            }
        }

        /// <summary>
        /// Convert key usages
        /// </summary>
        internal static int ConvertUsages(X509KeyUsageFlags usageFlags) => (int)usageFlags;

        /// <summary>
        /// Convert the bouncyCastle certificate and private key to an X509Certificate2
        /// </summary>
        /// <param name="certificate">The certificate to generate</param>
        /// <param name="friendlyName">The friendly name of the certificate</param>
        /// <param name="privateKey">The private key</param>
        internal static X509Certificate2 ConvertToX509Certificate2(String friendlyName, Org.BouncyCastle.X509.X509Certificate certificate, AsymmetricKeyParameter privateKey)
        {
            var password = Guid.NewGuid().ToString();
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var pfx = new Pkcs12Store();
            var certificateEntry = new X509CertificateEntry(certificate);
            pfx.SetCertificateEntry(friendlyName, certificateEntry);
            if (privateKey != null)
            {
                pfx.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(privateKey), new[] { certificateEntry });
            }
            using (var ms = new MemoryStream())
            {
                pfx.Save(ms, password.ToCharArray(), random);
                ms.Seek(0, SeekOrigin.Begin);
                return new X509Certificate2(ms.ToArray(), password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.DefaultKeySet);
            }
        }

        /// <summary>
        /// Generate the private key
        /// </summary>
        internal static AsymmetricCipherKeyPair GeneratePrivateKey(int keyLength)
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var keyGenerationParameters = new KeyGenerationParameters(random, keyLength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }

        /// <summary>
        /// Convert distinguished name
        /// </summary>
        internal static X509Name ConvertDN(X500DistinguishedName dn)
        {
            return new X509Name(dn.Decode(X500DistinguishedNameFlags.None));
        }

    }
}
#pragma warning restore