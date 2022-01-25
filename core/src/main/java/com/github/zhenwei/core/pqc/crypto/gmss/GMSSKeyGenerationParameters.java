package com.github.zhenwei.core.pqc.crypto.gmss;

import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class GMSSKeyGenerationParameters
    extends KeyGenerationParameters {

  private GMSSParameters params;

  public GMSSKeyGenerationParameters(
      SecureRandom random,
      GMSSParameters params) {
    // XXX key size?
    super(random, 1);
    this.params = params;
  }

  public GMSSParameters getParameters() {
    return params;
  }
}