package com.github.zhenwei.sdk.builder.pkcs7;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.pkcs.SignerInfo;
import com.github.zhenwei.core.asn1.x509.Certificate;
import com.github.zhenwei.core.enums.SignAlgEnum;
import com.github.zhenwei.core.exception.WeGooEnvelopException;
import java.security.cert.X509Certificate;

public class Pkcs7Builder extends AbstractPkcs7Builder{

    @Override
    SignerInfo genSignerInfo(ASN1Integer version, Certificate certificate, SignAlgEnum signAlgEnum,
        byte[] digest, byte[] signature) {

        return null;
    }

    @Override
    ASN1Encodable enveloped(X509Certificate certificate, byte[] data) throws WeGooEnvelopException {
        return null;
    }
}
