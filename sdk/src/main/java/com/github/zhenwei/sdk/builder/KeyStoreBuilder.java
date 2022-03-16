package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class KeyStoreBuilder {

    public byte[] genJks(PrivateKey privateKey,String alias,String passWd, X509Certificate[] certChain) throws WeGooCryptoException {
        try {
            KeyStore store = KeyStore.getInstance("jks", new WeGooProvider());
            store.load(null);
            store.setKeyEntry(alias,privateKey,passWd.toCharArray(),certChain);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            store.store(outputStream, passWd.toCharArray());
            return outputStream.toByteArray();
        } catch (Exception e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.generate_jks_err,e);
        }
    }


}
