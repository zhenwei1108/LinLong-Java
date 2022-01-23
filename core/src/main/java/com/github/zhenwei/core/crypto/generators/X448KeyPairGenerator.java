package com.github.zhenwei.core.crypto.generators;


import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPair;
import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import com.github.zhenwei.core.crypto.params.X448PrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.X448PublicKeyParameters;
import java.security.SecureRandom;

public class X448KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator {

  private SecureRandom random;

  public void init(KeyGenerationParameters parameters) {
    this.random = parameters.getRandom();
  }

  public AsymmetricCipherKeyPair generateKeyPair() {
    X448PrivateKeyParameters privateKey = new X448PrivateKeyParameters(random);
    X448PublicKeyParameters publicKey = privateKey.generatePublicKey();
    return new AsymmetricCipherKeyPair(publicKey, privateKey);
  }
}