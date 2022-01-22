package com.github.zhenwei.pkix.cert.path;

import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import java.util.HashSet;
import java.util.Set;
 

class CertPathUtils
{
    static Set getCriticalExtensionsOIDs(X509CertificateHolder[] certificates)
    {
        Set criticalExtensions = new HashSet();

        for (int i = 0; i != certificates.length; i++)
        {
            criticalExtensions.addAll(certificates[i].getCriticalExtensionOIDs());
        }

        return criticalExtensions;
    }
}