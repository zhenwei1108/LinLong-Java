package com.github.zhenwei.provider.jcajce.provider.asymmetric.util;

import com.github.zhenwei.core.crypto.BlockCipher;
import com.github.zhenwei.core.crypto.BufferedBlockCipher;
import com.github.zhenwei.provider.jce.spec.IESParameterSpec;

public class IESUtil {

  public static IESParameterSpec guessParameterSpec(BufferedBlockCipher iesBlockCipher,
      byte[] nonce) {
    if (iesBlockCipher == null) {
      return new IESParameterSpec(null, null, 128);
    } else {
      BlockCipher underlyingCipher = iesBlockCipher.getUnderlyingCipher();

      if (underlyingCipher.getAlgorithmName().equals("DES") ||
          underlyingCipher.getAlgorithmName().equals("RC2") ||
          underlyingCipher.getAlgorithmName().equals("RC5-32") ||
          underlyingCipher.getAlgorithmName().equals("RC5-64")) {
        return new IESParameterSpec(null, null, 64, 64, nonce);
      } else if (underlyingCipher.getAlgorithmName().equals("SKIPJACK")) {
        return new IESParameterSpec(null, null, 80, 80, nonce);
      } else if (underlyingCipher.getAlgorithmName().equals("GOST28147")) {
        return new IESParameterSpec(null, null, 256, 256, nonce);
      }

      return new IESParameterSpec(null, null, 128, 128, nonce);
    }
  }
}