package com.github.zhenwei.pkix.operator;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;

public interface InputExpanderProvider {

  InputExpander get(AlgorithmIdentifier algorithm);
}