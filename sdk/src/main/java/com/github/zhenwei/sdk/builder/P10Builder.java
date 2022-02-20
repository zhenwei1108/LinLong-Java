package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.pkix.pkcs.PKCS10CertificationRequest;
import com.github.zhenwei.sdk.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;
import com.github.zhenwei.sdk.util.Base64Util;

import java.io.IOException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.List;

public class P10Builder {

    private PKCS10CertificationRequest request;

    public P10Builder(byte[] data) throws WeGooCryptoException {
        try {
            request = new PKCS10CertificationRequest(data);
        } catch (Exception e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.parse_p10_err);
        }
    }

    public String getSubjectDN() throws IOException {
        return request.getSubject().toString();
    }

    public PublicKey getPublicKey() {
        return (PublicKey) request.getSubjectPublicKeyInfo();
    }

    public String getP10() throws WeGooCryptoException {
        try {
            return Base64Util.encode(request.getEncoded());
        } catch (Exception e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.encode_err, e);
        }
    }


    public P10Builder(String dn, PublicKey publicKey, Signature signature, List<Object> list){


    }

}