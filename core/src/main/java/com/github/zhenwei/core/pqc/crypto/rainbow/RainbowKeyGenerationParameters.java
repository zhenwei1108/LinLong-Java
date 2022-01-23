package com.github.zhenwei.core.pqc.crypto.rainbow;

import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;


public class RainbowKeyGenerationParameters
    extends KeyGenerationParameters {

  private RainbowParameters params;

  public RainbowKeyGenerationParameters(
      SecureRandom random,
      RainbowParameters params) {
    // TODO: key size?
    super(random, params.getVi()[params.getVi().length - 1] - params.getVi()[0]);
    this.params = params;
  }

  public RainbowParameters getParameters() {
    return params;
  }
}