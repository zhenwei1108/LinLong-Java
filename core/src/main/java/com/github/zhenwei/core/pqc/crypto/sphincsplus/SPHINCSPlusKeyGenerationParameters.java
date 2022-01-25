package com.github.zhenwei.core.pqc.crypto.sphincsplus;

import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class SPHINCSPlusKeyGenerationParameters
    extends KeyGenerationParameters {

  private final SPHINCSPlusParameters parameters;

  public SPHINCSPlusKeyGenerationParameters(SecureRandom random, SPHINCSPlusParameters parameters) {
    super(random, -1);
    this.parameters = parameters;
  }

  SPHINCSPlusParameters getParameters() {
    return parameters;
  }
}