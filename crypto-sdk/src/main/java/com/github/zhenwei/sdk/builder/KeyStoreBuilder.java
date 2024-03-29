package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.core.exception.WeGooCryptoException;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

public class KeyStoreBuilder {

    public byte[] genJks(PrivateKey privateKey, String alias, String keyPassWd, String storePassWd, Certificate[] certChain) throws WeGooCryptoException {
        return generator("jks", privateKey, alias, keyPassWd, storePassWd, certChain);
    }

    public KeyStore parseJks(String passWd, byte[] jks) throws WeGooCryptoException {
        return parser("jks", passWd, jks);
    }

    public byte[] genP12(PrivateKey privateKey, String alias, String keyPassWd, String storePassWd, Certificate[] certChain) throws WeGooCryptoException {
        return generator("PKCS12", privateKey, alias, keyPassWd, storePassWd, certChain);
    }

    public KeyStore parser(String type, String passWd, byte[] jks) throws WeGooCryptoException {
        try {
            KeyStore store = KeyStore.getInstance(type, new WeGooProvider());
            ByteArrayInputStream stream = new ByteArrayInputStream(jks);
            store.load(stream, passWd.toCharArray());
            return store;
        } catch (Exception e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.parse_jks_err, e);
        }
    }

    public byte[] generator(String type, PrivateKey privateKey, String alias, String keyPassWd, String storePassWd, Certificate[] certChain) throws WeGooCryptoException {
        try {
            KeyStore store = KeyStore.getInstance(type, new WeGooProvider());
            store.load(null);
            store.setKeyEntry(alias, privateKey, keyPassWd.toCharArray(), certChain);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            store.store(outputStream, storePassWd.toCharArray());
            return outputStream.toByteArray();
        } catch (Exception e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.generate_jks_err, e);
        }
    }

}
