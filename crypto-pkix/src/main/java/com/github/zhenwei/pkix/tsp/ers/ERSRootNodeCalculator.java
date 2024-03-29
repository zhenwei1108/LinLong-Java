package com.github.zhenwei.pkix.tsp.ers;

import com.github.zhenwei.pkix.operator.DigestCalculator;
import com.github.zhenwei.pkix.util.asn1.tsp.PartialHashtree;

/**
 * Base interface for an implementation that calculates the root hash contained in the time-stamp
 * from the Merkle tree based on the partial hash-tree nodes.
 */
public interface ERSRootNodeCalculator {

  /**
   * Calculate the root hash of the Merkle tree from the partial hash-tree nodes.
   *
   * @param digCalc the digest calculator to use.
   * @param nodes   the partial hash-trees forming the basis of the Merkle tree.
   * @return the root hash of the Merkle tree.
   */
  byte[] computeRootHash(DigestCalculator digCalc, PartialHashtree[] nodes);
}