package com.github.zhenwei.core.pqc.crypto.newhope;

import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPair;
import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class NHKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator {

  private SecureRandom random;

  public void init(KeyGenerationParameters param) {
    this.random = param.getRandom();
  }

  public AsymmetricCipherKeyPair generateKeyPair() {
    byte[] pubData = new byte[NewHope.SENDA_BYTES];
    short[] secData = new short[NewHope.POLY_SIZE];

    NewHope.keygen(random, pubData, secData);

    return new AsymmetricCipherKeyPair(new NHPublicKeyParameters(pubData),
        new NHPrivateKeyParameters(secData));
  }
}