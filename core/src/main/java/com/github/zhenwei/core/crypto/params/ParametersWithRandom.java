package com.github.zhenwei.core.crypto.params;

import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.CryptoServicesRegistrar;
import java.security.SecureRandom;


public class ParametersWithRandom
    implements CipherParameters {

  private SecureRandom random;
  private CipherParameters parameters;

  public ParametersWithRandom(
      CipherParameters parameters,
      SecureRandom random) {
    this.random = CryptoServicesRegistrar.getSecureRandom(random);
    this.parameters = parameters;
  }

  public ParametersWithRandom(
      CipherParameters parameters) {
    this(parameters, null);
  }

  public SecureRandom getRandom() {
    return random;
  }

  public CipherParameters getParameters() {
    return parameters;
  }
}