package com.github.zhenwei.pkix.operator;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;

/**
 * The base interface for a provider of DigestCalculator implementations.
 */
public interface DigestCalculatorProvider {

  DigestCalculator get(AlgorithmIdentifier digestAlgorithmIdentifier)
      throws OperatorCreationException;
}