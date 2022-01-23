package com.github.zhenwei.core.crypto.params;


import com.github.zhenwei.core.crypto.CipherParameters;

public class AsymmetricKeyParameter
    implements CipherParameters {

  boolean privateKey;

  public AsymmetricKeyParameter(
      boolean privateKey) {
    this.privateKey = privateKey;
  }

  public boolean isPrivate() {
    return privateKey;
  }
}