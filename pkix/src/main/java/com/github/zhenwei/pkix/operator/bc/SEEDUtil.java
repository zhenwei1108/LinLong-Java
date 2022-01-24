package com.github.zhenwei.pkix.operator.bc;

import com.github.zhenwei.core.asn1.kisa.KISAObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;

class SEEDUtil
{
    static AlgorithmIdentifier determineKeyEncAlg()
    {
        // parameters absent
        return new AlgorithmIdentifier(
            KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap);
    }
}