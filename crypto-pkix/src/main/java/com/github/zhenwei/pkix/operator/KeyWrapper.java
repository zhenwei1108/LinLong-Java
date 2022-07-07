package com.github.zhenwei.pkix.operator;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;

public interface KeyWrapper {

  AlgorithmIdentifier getAlgorithmIdentifier();

  byte[] generateWrappedKey(GenericKey encryptionKey)
      throws OperatorException;
}