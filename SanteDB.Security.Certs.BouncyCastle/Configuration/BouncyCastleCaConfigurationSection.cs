using SanteDB.OrmLite.Configuration;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml.Serialization;

namespace SanteDB.Security.Certs.BouncyCastle.Configuration
{
    /// <summary>
    /// Bouncy castle CA configuration
    /// </summary>
    [XmlType(nameof(BouncyCastleCaConfigurationSection), Namespace = "http://santedb.org/configuration")]
    public class BouncyCastleCaConfigurationSection : OrmConfigurationBase
    {
    }
}
