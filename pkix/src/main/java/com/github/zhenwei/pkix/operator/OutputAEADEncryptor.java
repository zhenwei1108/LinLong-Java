package com.github.zhenwei.pkix.operator;

import org.bouncycastle.operator.AADProcessor;
import org.bouncycastle.operator.OutputEncryptor;

public interface OutputAEADEncryptor
    extends OutputEncryptor, AADProcessor
{

}