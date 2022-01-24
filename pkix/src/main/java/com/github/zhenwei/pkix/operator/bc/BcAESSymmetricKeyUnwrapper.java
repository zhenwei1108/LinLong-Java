package com.github.zhenwei.pkix.operator.bc;

import com.github.zhenwei.core.crypto.engines.AESWrapEngine;
import com.github.zhenwei.core.crypto.params.KeyParameter;

public class BcAESSymmetricKeyUnwrapper
    extends BcSymmetricKeyUnwrapper
{
    public BcAESSymmetricKeyUnwrapper(KeyParameter wrappingKey)
    {
        super(AESUtil.determineKeyEncAlg(wrappingKey), new AESWrapEngine(), wrappingKey);
    }
}