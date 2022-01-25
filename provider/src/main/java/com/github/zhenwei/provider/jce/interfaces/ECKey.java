package com.github.zhenwei.provider.jce.interfaces;

import com.github.zhenwei.provider.jce.spec.ECParameterSpec;

/**
 * generic interface for an Elliptic Curve Key.
 */
public interface ECKey {

  /**
   * return a parameter specification representing the EC domain parameters for the key.
   */
  public ECParameterSpec getParameters();
}