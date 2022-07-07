package com.github.zhenwei.provider.jce.interfaces;

import com.github.zhenwei.provider.jce.spec.ElGamalParameterSpec;
import javax.crypto.interfaces.DHKey;

public interface ElGamalKey
    extends DHKey {

  public ElGamalParameterSpec getParameters();
}