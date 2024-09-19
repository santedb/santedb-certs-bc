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
using Newtonsoft.Json;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Serialization;

namespace SanteDB.Security.Certs.BouncyCastle.Configuration
{

    /// <summary>
    /// Certificate signing purpose
    /// </summary>
    [Flags, XmlType(nameof(BouncyCastleCertificateSignPurpose), Namespace = "http://santedb.org/configuration")]
    public enum BouncyCastleCertificateSignPurpose
    {
        /// <summary>
        /// This certificate should be used to sign other CA certs (it is a root)
        /// </summary>
        [XmlEnum("ca")]
        CertificateAuthority = 0x1,
        /// <summary>
        /// This certificate should be used to sign code certificates
        /// </summary>
        [XmlEnum("code")]
        CodeSigning = 0x2,
        /// <summary>
        /// This certificate should be used to sign server authentication requests
        /// </summary>
        [XmlEnum("server")]
        ServerAuth = 0x4,
        /// <summary>
        /// This certificate should be used to sign client authentication requests
        /// </summary>
        [XmlEnum("client")]
        ClientAuth = 0x8,
        /// <summary>
        /// Certificate should be used for smart cards
        /// </summary>
        [XmlEnum("smart-card")]
        SmartCards = 0x10
    }

    /// <summary>
    /// Certificate initialization settings
    /// </summary>
    [XmlType(nameof(BouncyCastleCertificateInitializationSettings), Namespace = "http://santedb.org/configuration")]
    public class BouncyCastleCertificateInitializationSettings
    {

        /// <summary>
        /// Gets or sets the friendly name
        /// </summary>
        [XmlAttribute("friendly"), JsonProperty("friendly")]
        public string FrienlyName { get; set; }

        /// <summary>
        /// Gets or sets the purpose of this certificate
        /// </summary>
        [XmlAttribute("purpose"), JsonProperty("purpose")]
        public BouncyCastleCertificateSignPurpose Purpose { get; set; }

        /// <summary>
        /// Gets the common name
        /// </summary>
        [XmlAttribute("cn"), JsonProperty("cn")]
        public string CommonName { get; set; }

        /// <summary>
        /// Gets the OU
        /// </summary>
        [XmlAttribute("ou"), JsonProperty("ou")]
        public string OrganizationUnit { get; set; }

        /// <summary>
        /// GEts the organization
        /// </summary>
        [XmlAttribute("o"), JsonProperty("o")]
        public string Organization { get; set; }

        /// <summary>
        /// Gets the locality
        /// </summary>
        [XmlAttribute("l"), JsonProperty("l")]
        public string Locality { get; set; }

        /// <summary>
        /// Gets the state
        /// </summary>
        [XmlAttribute("s"), JsonProperty("s")]
        public string State { get; set; }

        /// <summary>
        /// Gets the country
        /// </summary>
        [XmlAttribute("c"), JsonProperty("c")]
        public string Country { get; set; }


        /// <summary>
        /// Convert this setting a DN
        /// </summary>
        public X500DistinguishedName ToDistinguishedName()
        {
            StringBuilder sb = new StringBuilder();
            if (!string.IsNullOrEmpty(this.CommonName))
            {
                sb.AppendFormat(", CN={0}", this.CommonName);
            }
            if (!string.IsNullOrEmpty(this.OrganizationUnit))
            {
                sb.AppendFormat(", OU={0}", this.OrganizationUnit);
            }
            if (!string.IsNullOrEmpty(this.Organization))
            {
                sb.AppendFormat(", O={0}", this.Organization);
            }
            if (!string.IsNullOrEmpty(this.Locality))
            {
                sb.AppendFormat(", L={0}", this.Locality);
            }
            if (!string.IsNullOrEmpty(this.State))
            {
                sb.AppendFormat(", S={0}", this.State);
            }
            if (!string.IsNullOrEmpty(this.Country))
            {
                sb.AppendFormat(", C={0}", this.Country);
            }
            return new X500DistinguishedName(sb.ToString().Substring(2));
        }

        /// <inheritdoc/>
        public override string ToString() => $"{this.Purpose}: {this.ToDistinguishedName().Name}";

    }
}