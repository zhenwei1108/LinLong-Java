package com.github.zhenwei.pkix.tsp.ers;

import com.github.zhenwei.pkix.operator.DigestCalculator;

/**
 * General interface for an ERSData data group object.
 */
public interface ERSData {

  /**
   * Return the calculated hash for the Data
   *
   * @param digestCalculator digest calculator to use.
   * @return calculated hash.
   */
  byte[] getHash(DigestCalculator digestCalculator);
}