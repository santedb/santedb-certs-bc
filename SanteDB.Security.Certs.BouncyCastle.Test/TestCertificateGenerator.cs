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
 * Date: 2023-5-19
 */
using NUnit.Framework;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SanteDB.Security.Certs.BouncyCastle.Test
{
    [TestFixture]
    [ExcludeFromCodeCoverage]
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
            var csr = generator.CreateSigningRequest(keyPair, new X500DistinguishedName("CN=lumon.santesuite.net, DC=lumon, DC=santesuite.net, OID.2.5.6.11=SanteDB, OID.2.5.6.14=SomeMachine, OU=Optics and Design, C=Kier, E=admin@lumon.santesuite.net"), X509KeyUsageFlags.DataEncipherment);
            using (var fs = File.Create(Path.Combine(Path.GetDirectoryName(typeof(TestCertificateGenerator).Assembly.Location), "test.csr")))
            {
                fs.Write(csr, 0, csr.Length);
            }

        }

        [Test]
        public void TestCanGenerateSelfSignedCertificate()
        {
            var generator = new BouncyCastleCertificateGenerator();
            var keyPair = generator.CreateKeyPair(2048);
            var selfSignedCertificate = generator.CreateSelfSignedCertificate(keyPair, new X500DistinguishedName("CN=lumon.santesuite.net, DC=lumon, DC=santesuite.net, OID.2.5.6.11=SanteDB, OID.2.5.6.14=SomeMachine, OU=Macrodata Refinement, C=Kier, E=admin@lumon.santesuite.net"), new System.TimeSpan(1, 0, 0, 0), X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyAgreement, friendlyName: $"Lumon Industries Test Certificate");
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