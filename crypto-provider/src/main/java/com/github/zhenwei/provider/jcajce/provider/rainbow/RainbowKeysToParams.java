package com.github.zhenwei.provider.jcajce.provider.rainbow;

import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import com.github.zhenwei.core.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;


/**
 * utility class for converting jce/jca Rainbow objects objects into their
 * com.github.zhenwei.core.crypto counterparts.
 */

public class RainbowKeysToParams {

  static public AsymmetricKeyParameter generatePublicKeyParameter(
      PublicKey key)
      throws InvalidKeyException {
    if (key instanceof BCRainbowPublicKey) {
      BCRainbowPublicKey k = (BCRainbowPublicKey) key;

      return new RainbowPublicKeyParameters(k.getDocLength(), k.getCoeffQuadratic(),
          k.getCoeffSingular(), k.getCoeffScalar());
    }

    throw new InvalidKeyException("can't identify Rainbow public key: " + key.getClass().getName());
  }

  static public AsymmetricKeyParameter generatePrivateKeyParameter(
      PrivateKey key)
      throws InvalidKeyException {
    if (key instanceof BCRainbowPrivateKey) {
      BCRainbowPrivateKey k = (BCRainbowPrivateKey) key;
      return new RainbowPrivateKeyParameters(k.getInvA1(), k.getB1(),
          k.getInvA2(), k.getB2(), k.getVi(), k.getLayers());
    }

    throw new InvalidKeyException("can't identify Rainbow private key.");
  }
}