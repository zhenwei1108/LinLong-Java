package com.github.zhenwei.core.pqc.crypto.lms;

import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPair;
import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;


public class LMSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator {

  LMSKeyGenerationParameters param;

  public void init(KeyGenerationParameters param) {
    this.param = (LMSKeyGenerationParameters) param;
  }

  public AsymmetricCipherKeyPair generateKeyPair() {
    SecureRandom source = param.getRandom();

    byte[] I = new byte[16];
    source.nextBytes(I);

    byte[] rootSecret = new byte[32];
    source.nextBytes(rootSecret);

    LMSPrivateKeyParameters privKey = LMS.generateKeys(param.getParameters().getLMSigParam(),
        param.getParameters().getLMOTSParam(), 0, I, rootSecret);

    return new AsymmetricCipherKeyPair(privKey.getPublicKey(), privKey);
  }
}