package com.github.zhenwei.core.crypto.params;

import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class DHKeyGenerationParameters
    extends KeyGenerationParameters {

  private DHParameters params;

  public DHKeyGenerationParameters(
      SecureRandom random,
      DHParameters params) {
    super(random, getStrength(params));

    this.params = params;
  }

  public DHParameters getParameters() {
    return params;
  }

  static int getStrength(DHParameters params) {
    return params.getL() != 0 ? params.getL() : params.getP().bitLength();
  }
}