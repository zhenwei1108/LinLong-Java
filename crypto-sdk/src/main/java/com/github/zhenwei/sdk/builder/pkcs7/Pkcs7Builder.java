package com.github.zhenwei.sdk.builder.pkcs7;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.x509.Certificate;
import com.github.zhenwei.core.enums.SignAlgEnum;

import java.security.cert.X509CRL;

public class Pkcs7Builder extends AbstractPkcs7Builder{

    @Override
    ASN1Encodable genSignedData(byte[] data, SignAlgEnum signAlgEnum, byte[] signature, Certificate[] certificates, X509CRL[] crls, boolean isAttach) {
        return null;
    }
}
