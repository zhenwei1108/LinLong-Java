package com.github.zhenwei.core.crypto.params;

import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAKeyGenerationParameters
    extends KeyGenerationParameters {

  private BigInteger publicExponent;
  private int certainty;

  public RSAKeyGenerationParameters(
      BigInteger publicExponent,
      SecureRandom random,
      int strength,
      int certainty) {
    super(random, strength);

    if (strength < 12) {
      throw new IllegalArgumentException("key strength too small");
    }

    //
    // public exponent cannot be even
    //
    if (!publicExponent.testBit(0)) {
      throw new IllegalArgumentException("public exponent cannot be even");
    }

    this.publicExponent = publicExponent;
    this.certainty = certainty;
  }

  public BigInteger getPublicExponent() {
    return publicExponent;
  }

  public int getCertainty() {
    return certainty;
  }
}