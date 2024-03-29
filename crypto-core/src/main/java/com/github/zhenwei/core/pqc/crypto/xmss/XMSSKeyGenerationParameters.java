package com.github.zhenwei.core.pqc.crypto.xmss;

import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

/**
 * XMSS key-pair generation parameters.
 */
public final class XMSSKeyGenerationParameters
    extends KeyGenerationParameters {

  private final XMSSParameters xmssParameters;

  /**
   * XMSSMT constructor...
   *
   * @param prng Secure random to use.
   */
  public XMSSKeyGenerationParameters(XMSSParameters xmssParameters, SecureRandom prng) {
    super(prng, -1);

    this.xmssParameters = xmssParameters;
  }

  public XMSSParameters getParameters() {
    return xmssParameters;
  }
}