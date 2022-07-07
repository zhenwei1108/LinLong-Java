package com.github.zhenwei.provider.jcajce.spec;

import com.github.zhenwei.core.util.Arrays;
import java.security.spec.AlgorithmParameterSpec;

public class UserKeyingMaterialSpec
    implements AlgorithmParameterSpec {

  private final byte[] userKeyingMaterial;

  public UserKeyingMaterialSpec(byte[] userKeyingMaterial) {
    this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);
  }

  public byte[] getUserKeyingMaterial() {
    return Arrays.clone(userKeyingMaterial);
  }
}