using Newtonsoft.Json;
using SanteDB.Core.Security.Configuration;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml.Serialization;

namespace SanteDB.Security.Certs.BouncyCastle.Configuration
{
    /// <summary>
    /// Configuration for certificate use
    /// </summary>
    [XmlType(nameof(BouncyCastleCertificatePurposeSetting), Namespace = "http://santedb.org/configuration")]
    public class BouncyCastleCertificatePurposeSetting : X509ConfigurationElement
    {
        /// <summary>
        /// Indicates the purpose of this certificate
        /// </summary>
        [XmlAttribute("purpose"), JsonProperty("purpose")]
        public BouncyCastleCertificateSignPurpose Purpose { get; set; }

        /// <inheritdoc/>
        public override string ToString() => $"{this.Purpose}: {base.ToString()}";
    }
}
