package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.gm.GMNamedCurves;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.enums.KeyEnum;
import com.github.zhenwei.sdk.enums.KeyPairAlgEnum;
import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;
import com.github.zhenwei.sdk.enums.exception.KeyExceptionMessageEnum;
import com.github.zhenwei.sdk.exception.BaseWeGooException;
import com.github.zhenwei.sdk.exception.WeGooKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyGenerator;
import lombok.val;
import lombok.var;

public final class KeyBuilder {

  private Provider provider;

  public KeyBuilder(Provider provider) {
    this.provider = provider;
  }

  public KeyPair buildKeyPair(KeyPairAlgEnum keyPairEnum) throws BaseWeGooException {
    try {
      var generator = KeyPairGenerator.getInstance(keyPairEnum.getAlg(), provider);
      if (keyPairEnum == KeyPairAlgEnum.SM2_256) {
        //SM2 算法曲线
        var name = GMNamedCurves.getName(GMObjectIdentifiers.sm2p256v1);
        var sm2Spec = new ECGenParameterSpec(name);
        generator.initialize(sm2Spec, new SecureRandom());
      } else {
        generator.initialize(keyPairEnum.getKeyLen());
      }
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new WeGooKeyException(KeyExceptionMessageEnum.generate_keypair_err, e);
    }
  }

  public Key buildKey(KeyEnum keyEnum) throws BaseWeGooException {
    try {
      val generator = KeyGenerator.getInstance(keyEnum.getAlg(), provider);
      generator.init(keyEnum.getKeyLen(), new SecureRandom());
      return generator.generateKey();
    } catch (Exception e) {
      throw new WeGooKeyException(KeyExceptionMessageEnum.generate_key_err, e);
    }
  }

  public PublicKey covertSm2PublicKey(byte[] publicKey) throws WeGooKeyException {
    try {
      SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(publicKey);
      if (keyInfo != null) {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey);
        KeyFactory factory = KeyFactory.getInstance(
            keyInfo.getAlgorithm().getAlgorithm().toString(),
            new WeGooProvider());
        return factory.generatePublic(spec);
      } else {
        throw new WeGooKeyException(IExceptionEnum.params_err);
      }
    } catch (Exception e) {
      throw new WeGooKeyException(KeyExceptionMessageEnum.structure_public_key_err, e);
    }
  }

}