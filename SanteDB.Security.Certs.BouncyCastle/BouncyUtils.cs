using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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

        internal static Org.BouncyCastle.X509.X509Certificate CreateSelfSignedCertificate(X509Name subjectDn, AsymmetricCipherKeyPair keyPair, TimeSpan validityPeriod, X509KeyUsageFlags usageFlags, bool isCaCertificate)
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
            ConvertUsages(usageFlags).ToList().ForEach(u => certificateGenerator.AddExtension(X509Extensions.KeyUsage.Id, false, new KeyUsage(u)));
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false, new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public), new GeneralNames(new GeneralName(subjectDn)), serialNumber));
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, false, new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public)));
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, false, new BasicConstraints(isCaCertificate));
            return certificateGenerator.Generate(keyPair.Private, random);
        }

        /// <summary>
        /// Convert key usages
        /// </summary>
        internal static IEnumerable<int> ConvertUsages(X509KeyUsageFlags usageFlags)
        {
            foreach (X509KeyUsageFlags use in Enum.GetValues(typeof(X509KeyUsageFlags)))
            {
                if (usageFlags.HasFlag(use))
                {
                    switch (use)
                    {
                        case X509KeyUsageFlags.CrlSign:
                            yield return KeyUsage.CrlSign;
                            break;
                        case X509KeyUsageFlags.DataEncipherment:
                            yield return KeyUsage.DataEncipherment;
                            break;
                        case X509KeyUsageFlags.DecipherOnly:
                            yield return KeyUsage.DecipherOnly;
                            break;
                        case X509KeyUsageFlags.DigitalSignature:
                            yield return KeyUsage.DigitalSignature;
                            break;
                        case X509KeyUsageFlags.EncipherOnly:
                            yield return KeyUsage.EncipherOnly;
                            break;
                        case X509KeyUsageFlags.KeyAgreement:
                            yield return KeyUsage.KeyAgreement;
                            break;
                        case X509KeyUsageFlags.KeyCertSign:
                            yield return KeyUsage.KeyCertSign;
                            break;
                        case X509KeyUsageFlags.KeyEncipherment:
                            yield return KeyUsage.KeyEncipherment;
                            break;
                        case X509KeyUsageFlags.NonRepudiation:
                            yield return KeyUsage.NonRepudiation;
                            break;
                    }
                }
            }
        }

        /// <summary>
        /// Convert the bouncyCastle certificate and private key to an X509Certificate2
        /// </summary>
        /// <param name="certificate">The certificate to generate</param>
        /// <param name="privateKey">The private key</param>
        internal static X509Certificate2 ConvertToX509Certificate2(Org.BouncyCastle.X509.X509Certificate certificate, AsymmetricKeyParameter privateKey)
        {
            var password = Guid.NewGuid().ToString();
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var pfx = new Pkcs12Store();
            var certificateEntry = new X509CertificateEntry(certificate);
            pfx.SetCertificateEntry("my", certificateEntry);
            pfx.SetKeyEntry("my", new AsymmetricKeyEntry(privateKey), new[] { certificateEntry });
            using (var ms = new MemoryStream())
            {
                pfx.Save(ms, password.ToCharArray(), random);
                ms.Seek(0, SeekOrigin.Begin);
                return new X509Certificate2(ms.ToArray(), password, X509KeyStorageFlags.PersistKeySet);
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
