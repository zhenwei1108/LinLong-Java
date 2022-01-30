package com.github.zhenwei.sdk.key;

import com.github.zhenwei.core.asn1.gm.GMNamedCurves;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.enums.KeyAlgEnum;
import com.github.zhenwei.sdk.enums.exception.KeyExceptionMessageEnum;
import com.github.zhenwei.sdk.exception.BaseWeGooException;
import com.github.zhenwei.sdk.exception.WeGooKeyException;
import lombok.var;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class KeyBuilder {

    private Provider provider;

    public KeyBuilder(Provider provider) {
        this.provider = provider;
    }

    public <T> T build(KeyAlgEnum keyAlgEnum) throws BaseWeGooException {
        try {
            /**
             * 非对称密钥
             */
            if (keyAlgEnum.isAsymm()) {
                return (T) genKeyPair(keyAlgEnum);
            }else {
                return (T) genKey(keyAlgEnum);
            }

        } catch (Exception e) {
            throw new WeGooKeyException(KeyExceptionMessageEnum.generate_key_err, e);
        }

    }


    private KeyPair genKeyPair(KeyAlgEnum keyAlgEnum) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        var generator = KeyPairGenerator.getInstance(keyAlgEnum.getAlg(), provider);
        if (keyAlgEnum == KeyAlgEnum.SM2_256) {
            //SM2 算法曲线
            var name = GMNamedCurves.getName(GMObjectIdentifiers.sm2p256v1);
            var sm2Spec = new ECGenParameterSpec(name);
            generator.initialize(sm2Spec, new SecureRandom());
        } else {
            generator.initialize(keyAlgEnum.getKeyLen());
        }
        return generator.generateKeyPair();
    }

    private SecretKey genKey(KeyAlgEnum keyAlgEnum) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance(keyAlgEnum.getAlg(), provider);
        generator.init(keyAlgEnum.getKeyLen(), new SecureRandom());
        return generator.generateKey();
    }



    public static void main(String[] args) throws BaseWeGooException {
        KeyBuilder keyBuilder = new KeyBuilder(new WeGooProvider());
        KeyPair pair = keyBuilder.build(KeyAlgEnum.SM2_256);
        Key build = keyBuilder.build(KeyAlgEnum.AES_128);
        Key key = keyBuilder.build(KeyAlgEnum.SM2_256);
    }

}