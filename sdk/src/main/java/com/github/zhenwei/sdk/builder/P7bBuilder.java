package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.pkcs.ContentInfo;
import com.github.zhenwei.core.asn1.pkcs.SignedData;
import com.github.zhenwei.core.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.core.exception.WeGooCryptoException;

import java.security.cert.X509Certificate;
import java.util.ArrayList;

/**
 * @description: P7bBuilder
 *  证书链
 * @author: zhangzhenwei
 * @since: 1.0.1
 * @date: 2022/6/4  17:24
 */
public class P7bBuilder {

    public static ArrayList<X509Certificate> buildP7b(byte[] data) throws WeGooCryptoException {
        ContentInfo contentInfo = ContentInfo.getInstance(data);
        //P7B 的 contentType应该是这个
//        ASN1ObjectIdentifier signedData = PKCSObjectIdentifiers.signedData;
        SignedData signedData = SignedData.getInstance(contentInfo.getContent());
        if (signedData == null) throw new WeGooCryptoException(CryptoExceptionMassageEnum.build_err);
        ASN1Set certs = signedData.getCertificates();
        ArrayList<X509Certificate> list = new ArrayList<>();
        for (ASN1Encodable cert : certs) {
            list.add(CertBuilder.getInstance(cert).getCert());
        }
        return list;
    }

}
