package com.github.zhenwei.core.pqc.crypto.sphincs;

import com.github.zhenwei.core.util.Arrays;

public class SPHINCSPrivateKeyParameters
    extends SPHINCSKeyParameters {

  private final byte[] keyData;

  public SPHINCSPrivateKeyParameters(byte[] keyData) {
    super(true, null);
    this.keyData = Arrays.clone(keyData);
  }

  public SPHINCSPrivateKeyParameters(byte[] keyData, String treeDigest) {
    super(true, treeDigest);
    this.keyData = Arrays.clone(keyData);
  }

  public byte[] getKeyData() {
    return Arrays.clone(keyData);
  }
}