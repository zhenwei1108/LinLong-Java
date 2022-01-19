package com.github.zhenwei.pkix.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.InputExpander;

public interface InputExpanderProvider
{
    InputExpander get(AlgorithmIdentifier algorithm);
}