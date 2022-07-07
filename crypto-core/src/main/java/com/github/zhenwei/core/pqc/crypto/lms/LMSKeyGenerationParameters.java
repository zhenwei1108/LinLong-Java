package com.github.zhenwei.core.pqc.crypto.lms;

import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class LMSKeyGenerationParameters
    extends KeyGenerationParameters {

  private final LMSParameters lmsParameters;

  /**
   * Base constructor - parameters and a source of randomness.
   *
   * @param lmsParameters LMS parameter set to use.
   * @param random        the random byte source.
   */
  public LMSKeyGenerationParameters(LMSParameters lmsParameters, SecureRandom random) {
    super(random, LmsUtils.calculateStrength(lmsParameters)); // TODO: need something for "strength"
    this.lmsParameters = lmsParameters;
  }

  public LMSParameters getParameters() {
    return lmsParameters;
  }
}