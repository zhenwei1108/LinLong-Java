package com.github.zhenwei.core.crypto.params;

import com.github.zhenwei.core.crypto.CipherParameters;

public class DHMQVPublicParameters
    implements CipherParameters {

  private DHPublicKeyParameters staticPublicKey;
  private DHPublicKeyParameters ephemeralPublicKey;

  public DHMQVPublicParameters(
      DHPublicKeyParameters staticPublicKey,
      DHPublicKeyParameters ephemeralPublicKey) {
    if (staticPublicKey == null) {
      throw new NullPointerException("staticPublicKey cannot be null");
    }
    if (ephemeralPublicKey == null) {
      throw new NullPointerException("ephemeralPublicKey cannot be null");
    }
    if (!staticPublicKey.getParameters().equals(ephemeralPublicKey.getParameters())) {
      throw new IllegalArgumentException(
          "Static and ephemeral public keys have different domain parameters");
    }

    this.staticPublicKey = staticPublicKey;
    this.ephemeralPublicKey = ephemeralPublicKey;
  }

  public DHPublicKeyParameters getStaticPublicKey() {
    return staticPublicKey;
  }

  public DHPublicKeyParameters getEphemeralPublicKey() {
    return ephemeralPublicKey;
  }
}