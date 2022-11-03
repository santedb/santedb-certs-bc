using NUnit.Framework;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SanteDB.Security.Certs.BouncyCastle.Test
{
    [TestFixture]
    public class TestCertificateGenerator
    {

        [Test]
        public void TestCanGeneratePrivateKeyPair()
        {
            var generator = new BouncyCastleCertificateGenerator();
            var keyPair = generator.CreateKeyPair(1024);
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(keyPair);

                byte[] someData = new byte[] { 0x5, 0x8, 0x30, 0x99, 0x39, 0x13 };
                var encryptedData = rsa.Encrypt(someData, RSAEncryptionPadding.Pkcs1);
                var decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.Pkcs1);
                Assert.AreEqual(someData, decryptedData);
            }
        }

        [Test]
        public void TestCanGenerateSigningRequest()
        {
            var generator = new BouncyCastleCertificateGenerator();
            var keyPair = generator.CreateKeyPair(1024);
            var csr = generator.CreateSigningRequest(keyPair, new X500DistinguishedName("CN=lumon.santesuite.net, OU=Optics and Design, C=Kier, E=admin@lumon.santesuite.net"), X509KeyUsageFlags.DataEncipherment);
            using (var fs = File.CreateText(Path.Combine(Path.GetDirectoryName(typeof(TestCertificateGenerator).Assembly.Location), "test.csr")))
            {
                fs.WriteLine("---------- BEGIN CERTIFICATE REQUEST -------------");
                fs.WriteLine(Convert.ToBase64String(csr));
                fs.WriteLine("---------- END CERTIFICATE REQUEST -------------");
            }

        }

        [Test]
        public void TestCanGenerateSelfSignedCertificate()
        {
            var generator = new BouncyCastleCertificateGenerator();
            var keyPair = generator.CreateKeyPair(1024);
            var selfSignedCertificate = generator.CreateSelfSignedCertificate(keyPair, new X500DistinguishedName("CN=lumon.santesuite.net, OU=Macrodata Refinement, C=Kier, E=admin@lumon.santesuite.net"), new System.TimeSpan(1, 0, 0, 0), X509KeyUsageFlags.DataEncipherment);
            Assert.IsTrue(selfSignedCertificate.HasPrivateKey);

            using (var rsa = selfSignedCertificate.GetRSAPrivateKey())
            {
                byte[] someData = new byte[] { 0x5, 0x8, 0x30, 0x99, 0x39, 0x13 };
                var encryptedData = rsa.Encrypt(someData, RSAEncryptionPadding.Pkcs1);
                var decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.Pkcs1);
                Assert.AreEqual(someData, decryptedData);
            }


            var exportCertificate = selfSignedCertificate.Export(X509ContentType.Cert);
            using (var fs = File.Create(Path.Combine(Path.GetDirectoryName(typeof(TestCertificateGenerator).Assembly.Location), "test.cer")))
            {
                fs.Write(exportCertificate, 0, exportCertificate.Length);
            }
        }
    }
}