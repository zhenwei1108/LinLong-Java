package com.github.zhenwei.core.crypto.params;

import com.github.zhenwei.core.crypto.DerivationParameters;

/**
 * parameters for Key derivation functions for IEEE P1363a
 */
public class KDFParameters
    implements DerivationParameters {

  byte[] iv;
  byte[] shared;

  public KDFParameters(
      byte[] shared,
      byte[] iv) {
    this.shared = shared;
    this.iv = iv;
  }

  public byte[] getSharedSecret() {
    return shared;
  }

  public byte[] getIV() {
    return iv;
  }
}