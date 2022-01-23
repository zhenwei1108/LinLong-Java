package com.github.zhenwei.core.crypto.params;

import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;


public class X448KeyGenerationParameters
    extends KeyGenerationParameters {

  public X448KeyGenerationParameters(SecureRandom random) {
    super(random, 448);
  }
}