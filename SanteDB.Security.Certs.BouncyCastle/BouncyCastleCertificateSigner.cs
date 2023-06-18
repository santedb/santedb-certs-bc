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
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using SanteDB.Core.Diagnostics;
using SanteDB.Core.i18n;
using SanteDB.Core.Security;
using SanteDB.Core.Security.Certs;
using SanteDB.Core.Security.Services;
using SanteDB.Core.Services;
using SanteDB.Security.Certs.BouncyCastle.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SanteDB.Security.Certs.BouncyCastle
{
    /// <summary>
    /// Bouncy castle certificate signing service
    /// </summary>
    public class BouncyCastleCertificateSigner : ICertificateSigningService
    {

        // Configuration
        private readonly Tracer m_tracer = Tracer.GetTracer(typeof(BouncyCastleCertificateSigner));
        private readonly BouncyCastleConfigurationSection m_configuration;
        private readonly IPolicyEnforcementService m_pepService;
        private readonly IPlatformSecurityProvider m_platformSecurityService;
        private readonly Dictionary<BouncyCastleCertificateSignPurpose, X509Certificate2> m_signingCertificates = new Dictionary<BouncyCastleCertificateSignPurpose, X509Certificate2>();

        /// <summary>
        /// DI Constructor
        /// </summary>
        public BouncyCastleCertificateSigner(IConfigurationManager configurationManager, IPolicyEnforcementService policyEnforcement, IPlatformSecurityProvider platformSecurityProvider)
        {
            this.m_configuration = configurationManager.GetSection<BouncyCastleConfigurationSection>();
            this.m_pepService = policyEnforcement;
            this.m_platformSecurityService = platformSecurityProvider;
        }

        /// <summary>
        /// Initialize the signing manager
        /// </summary>
        private void InitializeOrThrow()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                if (this.m_signingCertificates.Any())
                {
                    return;
                }
                if (this.m_configuration?.SigningCertificates.Any() == true)
                {
                    this.m_configuration.SigningCertificates.ForEach(o =>
                    {
                        this.m_tracer.TraceInfo("Will use {0} to sign {1}", o.FindValue, o.Purpose);
                        var certificate = o.Certificate;
                        if (!certificate.Verify() || !certificate.HasPrivateKey)
                        {
                            throw new InvalidOperationException(String.Format(ErrorMessages.CERTIFICATE_NOT_VALID, certificate));
                        }
                        this.m_signingCertificates.Add(o.Purpose, certificate);
                    });
                }
                else if (this.m_configuration?.GenerateCertificates.Any() == true)
                {
                    this.m_configuration.GenerateCertificates.ForEach(o =>
                    {
                        if (!this.m_platformSecurityService.TryGetCertificate(X509FindType.FindByIssuerDistinguishedName, o.ToDistinguishedName(), out var certificate))
                        {
                            this.m_tracer.TraceInfo("Will generate new certificate {0}", o.ToDistinguishedName());
                            var subjectDn = BouncyUtils.ConvertDN(o.ToDistinguishedName());
                            var keyPair = BouncyUtils.GeneratePrivateKey(2048);
                            if (o.Purpose == BouncyCastleCertificateSignPurpose.CertificateAuthority)
                            {
                                var rootCa = BouncyUtils.CreateSelfSignedCertificate(subjectDn, new string[0], keyPair, new TimeSpan(7300, 0, 0, 0), X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true, null);
                                certificate = BouncyUtils.ConvertToX509Certificate2(o.FrienlyName, rootCa, keyPair.Private);
                                _ = this.m_platformSecurityService.TryInstallCertificate(certificate, storeName: StoreName.Root);
                            }
                            else
                            {
                                var immCsr = BouncyUtils.CreateSigningRequest(subjectDn, new string[0], keyPair, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, null, true);
                                if (this.m_signingCertificates.TryGetValue(BouncyCastleCertificateSignPurpose.CertificateAuthority, out var rootCertificate))
                                {
                                    var issuerKey = DotNetUtilities.GetKeyPair(rootCertificate.PrivateKey);
                                    var issuerCert = DotNetUtilities.FromX509Certificate(rootCertificate);
                                    var immCa = BouncyUtils.SignCertificateRequest(immCsr, new TimeSpan(3650, 0, 0, 0), issuerKey, issuerCert, BouncyCastleCertificateSignPurpose.CertificateAuthority);
                                    certificate = BouncyUtils.ConvertToX509Certificate2(o.FrienlyName, immCa, keyPair.Private);
                                }
                                _ = this.m_platformSecurityService.TryInstallCertificate(certificate, storeName: StoreName.CertificateAuthority);
                            }
                        }

                        this.m_tracer.TraceInfo("Will use {0} to sign {1}", certificate, o.Purpose);
                        if (!certificate.Verify() || !certificate.HasPrivateKey)
                        {
                            throw new InvalidOperationException(String.Format(ErrorMessages.CERTIFICATE_NOT_VALID, certificate));
                        }
                        this.m_signingCertificates.Add(o.Purpose, certificate);
                    });

                }
            }
        }

        /// <inheritdoc/>
        public string ServiceName => "Bouncy Castle Certificate Signer";

        /// <inheritdoc/>
        public IEnumerable<X509Certificate2> GetSigningCertificates()
        {
            this.InitializeOrThrow();
            return this.m_signingCertificates.Values;
        }

        /// <inheritdoc/>
        public X500DistinguishedName GetSigningRequestDN(byte[] request)
        {
            // Is the object in PEM format or DER format
            var csrData = BouncyUtils.ReadSigningRequest(request);
            return new X500DistinguishedName(csrData.GetCertificationRequestInfo().Subject.GetEncoded());
        }

        /// <inheritdoc/>
        public X509Certificate2 SignCertificateRequest(byte[] request, X509Certificate2 signWithCertificate)
        {
            this.InitializeOrThrow();
            this.m_pepService.Demand(PermissionPolicyIdentifiers.IssueCertificates);

            var certificateSelected = this.m_signingCertificates.FirstOrDefault(o => o.Value.Thumbprint == signWithCertificate.Thumbprint);
            if (certificateSelected.Value == null)
            {
                throw new InvalidOperationException(ErrorMessages.NOT_INITIALIZED);
            }

            var issuerKeyPair = DotNetUtilities.GetKeyPair(certificateSelected.Value.PrivateKey);
            var issuerCert = DotNetUtilities.FromX509Certificate(certificateSelected.Value);
            var csrRequest = BouncyUtils.ReadSigningRequest(request);
            var issuedCertificate = BouncyUtils.SignCertificateRequest(csrRequest, this.m_configuration.DefaultValidity, issuerKeyPair, issuerCert, certificateSelected.Key);
            return BouncyUtils.ConvertToX509Certificate2(issuedCertificate.SubjectDN.GetValueList(X509Name.CN).Cast<String>().First(), issuedCertificate, null);
        }
    }
}
