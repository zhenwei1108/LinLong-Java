package com.github.zhenwei.provider.jce.interfaces;

import com.github.zhenwei.core.math.ec.ECPoint;
import java.security.PublicKey;

/**
 * interface for elliptic curve public keys.
 */
public interface ECPublicKey
    extends ECKey, PublicKey {

  /**
   * return the public point Q
   */
  public ECPoint getQ();
}