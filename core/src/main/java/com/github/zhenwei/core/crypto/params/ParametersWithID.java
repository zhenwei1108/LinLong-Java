package com.github.zhenwei.core.crypto.params;


import com.github.zhenwei.core.crypto.CipherParameters;

public class ParametersWithID
    implements CipherParameters {

  private CipherParameters parameters;
  private byte[] id;

  public ParametersWithID(
      CipherParameters parameters,
      byte[] id) {
    this.parameters = parameters;
    this.id = id;
  }

  public byte[] getID() {
    return id;
  }

  public CipherParameters getParameters() {
    return parameters;
  }
}