package com.github.zhenwei.sdk.key;

import com.github.zhenwei.core.asn1.gm.GMNamedCurves;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.sdk.enums.KeyAlgEnum;
import com.github.zhenwei.sdk.enums.exception.KeyExceptionMessageEnum;
import com.github.zhenwei.sdk.exception.BaseWeGooException;
import com.github.zhenwei.sdk.exception.WeGooKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

public class KeyPairBuilder {

  private Provider provider;

  public KeyPairBuilder(Provider provider) {
    this.provider = provider;
  }

  public KeyPair build(KeyAlgEnum keyAlgEnum) throws BaseWeGooException {

    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlgEnum.getAlg(), provider);
      if (keyAlgEnum == KeyAlgEnum.SM2_256) {
        //SM2 算法曲线
        String name = GMNamedCurves.getName(GMObjectIdentifiers.sm2p256v1);
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec(name);
        generator.initialize(sm2Spec, new SecureRandom());
      } else {
        generator.initialize(keyAlgEnum.getKeyLen());
      }
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new WeGooKeyException(KeyExceptionMessageEnum.generate_key_err, e);
    }


  }


}