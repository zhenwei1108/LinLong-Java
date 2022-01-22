package com.github.zhenwei.pkix.operator.bc;


import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import kisa.KISAObjectIdentifiers;

class SEEDUtil
{
    static AlgorithmIdentifier determineKeyEncAlg()
    {
        // parameters absent
        return new AlgorithmIdentifier(
            KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap);
    }
}