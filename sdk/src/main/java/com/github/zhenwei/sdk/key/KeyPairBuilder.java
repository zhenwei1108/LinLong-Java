package com.github.zhenwei.sdk.key;

import com.github.zhenwei.core.asn1.gm.GMNamedCurves;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.sdk.enums.KeyAlgEnum;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

public class KeyPairBuilder {

  private Provider provider;

  public KeyPairBuilder(Provider provider) {
    this.provider = provider;
  }

  public void build(KeyAlgEnum keyAlgEnum)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {

    KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlgEnum.getAlg(), provider);
    if (keyAlgEnum == KeyAlgEnum.SM2_256) {
      //SM2 算法曲线
      String name = GMNamedCurves.getName(GMObjectIdentifiers.sm2p256v1);
      ECGenParameterSpec sm2Spec = new ECGenParameterSpec(name);
      generator.initialize(sm2Spec, new SecureRandom());
    } else {
      generator.initialize(keyAlgEnum.getKeyLen());
    }
    KeyPair keyPair = generator.generateKeyPair();
    System.out.println(keyPair);

  }


}