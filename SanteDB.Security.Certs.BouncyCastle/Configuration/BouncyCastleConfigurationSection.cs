using Newtonsoft.Json;
using SanteDB.Core.Configuration;
using SanteDB.Core.Security.Configuration;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;
using System.Xml.Serialization;

namespace SanteDB.Security.Certs.BouncyCastle.Configuration
{
    /// <summary>
    /// Bouncy castle configuration section
    /// </summary>
    [XmlType(nameof(BouncyCastleConfigurationSection), Namespace = "http://santedb.org/configuration")]
    public class BouncyCastleConfigurationSection : IEncryptedConfigurationSection
    {

        /// <summary>
        /// Creates a default signing configuration section
        /// </summary>
        public BouncyCastleConfigurationSection()
        {
            this.DefaultValidity = new TimeSpan(365, 0, 0, 0);
            this.SigningCertificates = new List<BouncyCastleCertificatePurposeSetting>();
            this.GenerateCertificates = new List<BouncyCastleCertificateInitializationSettings>();
        }

        /// <summary>
        /// Gets or sets the validity period
        /// </summary>
        [XmlElement("validity"), JsonProperty("validity")]
        public TimeSpan DefaultValidity { get; set; }

        /// <summary>
        /// Gets the signing certificate (if configured)
        /// </summary>
        [XmlArray("signingCertificates"), XmlArrayItem("add"), JsonProperty("signingCertificates")]
        [DisplayName("Signing Certificates"), Description("The existing X509 certificates which should be used to sign other certificates")]
        [TypeConverter(typeof(CollectionConverter))]
        public List<BouncyCastleCertificatePurposeSetting> SigningCertificates { get; set; }

        /// <summary>
        /// Gets the initialization parameters for a signing certificate if one is being used
        /// </summary>
        [XmlArray("generate"), XmlArrayItem("add"), JsonProperty("generate")]
        [DisplayName("Initialization"), Description("If allowing SanteDB to initialize new signing certificates - the parameters for the certificate generation process")]
        [TypeConverter(typeof(ExpandableObjectConverter))]
        public List<BouncyCastleCertificateInitializationSettings> GenerateCertificates { get; set; }

        /// <inheritdoc/>
        public override string ToString() => nameof(BouncyCastleConfigurationSection);

    }
}
