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
using SanteDB.Core.Configuration;
using SanteDB.Core.Configuration.Features;
using SanteDB.Core.Security.Certs;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SanteDB.Security.Certs.BouncyCastle.Configuration
{
    /// <summary>
    /// Bouncy castle configuration feature
    /// </summary>
    public class BouncyCastleCertificateGeneratorFeature : IFeature
    {

        private const string GenerateCertificateEnabledSetting = "Generate Certificates with BouncyCastle";
        private const string CertificateAuthorityEnabledSetting = "Sign Certificates with BouncyCastle";
        private const string CertificateAuthoritySetting = "Certificate Signature Settings";

        // Generic feature configuration
        private GenericFeatureConfiguration m_configuration;

        /// <summary>
        /// Certificate service name
        /// </summary>
        public string Name => "Certificate Services";

        /// <summary>
        /// Get the configuration type
        /// </summary>
        public Type ConfigurationType => typeof(GenericFeatureConfiguration);

        /// <summary>
        /// Gets or sets the configuration object
        /// </summary>
        public object Configuration
        {
            get => this.m_configuration;
            set => this.m_configuration = value as GenericFeatureConfiguration;
        }

        /// <summary>
        /// Gets the description of this feature
        /// </summary>
        public string Description => "Enables and configures how X509 certificates are generated and validated by this SanteDB instance";

        /// <summary>
        /// Flags for the feature
        /// </summary>
        public FeatureFlags Flags => FeatureFlags.None;

        /// <summary>
        /// Gets the group
        /// </summary>
        public string Group => FeatureGroup.Security;

        /// <summary>
        /// Create install tasks
        /// </summary>
        public IEnumerable<IConfigurationTask> CreateInstallTasks()
        {
            yield return new InstallServiceTask(this, typeof(BouncyCastleCertificateGenerator), () => (bool)this.m_configuration.Values[GenerateCertificateEnabledSetting] == true, typeof(ICertificateGeneratorService));
            yield return new InstallServiceTask(this, typeof(BouncyCastleCertificateSigner), () => (bool)this.m_configuration.Values[CertificateAuthorityEnabledSetting] == true, typeof(ICertificateSigningService));
            // TODO: Enable the certificate management service
            yield return new InstallConfigurationSectionTask(this, this.m_configuration.Values[CertificateAuthoritySetting] as IConfigurationSection, "Bouncy Castle Certificate Signing");
        }

        /// <summary>
        /// Create uninstall tasks
        /// </summary>
        public IEnumerable<IConfigurationTask> CreateUninstallTasks()
        {
            yield return new UnInstallServiceTask(this, typeof(BouncyCastleCertificateGenerator), () => (bool)this.m_configuration.Values[GenerateCertificateEnabledSetting] == false);
            yield return new UnInstallServiceTask(this, typeof(BouncyCastleCertificateSigner), () => (bool)this.m_configuration.Values[CertificateAuthorityEnabledSetting] == false);
            yield return new UnInstallConfigurationSectionTask(this, this.m_configuration.Values[CertificateAuthoritySetting] as IConfigurationSection, "Bouncy Castle Certificate Signing");
        }

        /// <summary>
        /// Query state
        /// </summary>
        public FeatureInstallState QueryState(SanteDBConfiguration configuration)
        {
            var sectionConfig = configuration.GetSection<BouncyCastleConfigurationSection>();
            var appServiceProviders = configuration.GetSection<ApplicationServiceContextConfigurationSection>().ServiceProviders;

            // Is the FILE based BI repository enabled?
            this.m_configuration = new GenericFeatureConfiguration();
            this.m_configuration.Options.Add(CertificateAuthorityEnabledSetting, () => ConfigurationOptionType.Boolean);
            this.m_configuration.Options.Add(GenerateCertificateEnabledSetting, () => ConfigurationOptionType.Boolean);
            this.m_configuration.Options.Add(CertificateAuthoritySetting, () => ConfigurationOptionType.Object);
            this.m_configuration.Values.Add(CertificateAuthorityEnabledSetting, appServiceProviders.Any(t => typeof(BouncyCastleCertificateSigner) == t.Type));
            this.m_configuration.Values.Add(GenerateCertificateEnabledSetting, appServiceProviders.Any(t => typeof(BouncyCastleCertificateGenerator) == t.Type));
            this.m_configuration.Values.Add(CertificateAuthoritySetting, sectionConfig ?? new BouncyCastleConfigurationSection()
            {
                DefaultValidity = new TimeSpan(365, 0, 0, 0),
                GenerateCertificates = new List<BouncyCastleCertificateInitializationSettings>()
                {
                    new BouncyCastleCertificateInitializationSettings()
                    {
                        Purpose = BouncyCastleCertificateSignPurpose.CertificateAuthority,
                        CommonName = "ca.mysite.santedb.org",
                        Country = "CA",
                        FrienlyName = "My CA Certificate",
                        Locality = "Demoville",
                        State = "Demo"
                    },
                    new BouncyCastleCertificateInitializationSettings()
                    {
                        Purpose = BouncyCastleCertificateSignPurpose.ServerAuth,
                        CommonName = "servers.ca.mysite.santedb.org",
                        Country = "CA",
                        FrienlyName = "My Server Intermediary Certificate",
                        Locality = "Demoville",
                        State = "Demo"
                    }
                },
                SigningCertificates = new List<BouncyCastleCertificatePurposeSetting>()
            });
            // Construct the configuration options
            return sectionConfig != null ? FeatureInstallState.Installed : FeatureInstallState.NotInstalled;
        }
    }
}
