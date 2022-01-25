package com.github.zhenwei.core.crypto.params;

import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class Ed448KeyGenerationParameters
    extends KeyGenerationParameters {

  public Ed448KeyGenerationParameters(SecureRandom random) {
    super(random, 448);
  }
}