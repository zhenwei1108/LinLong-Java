package com.github.zhenwei.core.pqc.crypto.mceliece;

import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class McElieceCCA2KeyGenerationParameters
    extends KeyGenerationParameters {

  private McElieceCCA2Parameters params;

  public McElieceCCA2KeyGenerationParameters(
      SecureRandom random,
      McElieceCCA2Parameters params) {
    // XXX key size?
    super(random, 128);
    this.params = params;
  }

  public McElieceCCA2Parameters getParameters() {
    return params;
  }
}