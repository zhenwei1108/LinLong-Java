package com.github.zhenwei.pkix.cms.bc;


import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.pkix.operator.GenericKey;
import org.bouncycastle.crypto.params.KeyParameter;


class CMSUtils
{
    static CipherParameters getBcKey(GenericKey key)
    {
        if (key.getRepresentation() instanceof CipherParameters)
        {
            return (CipherParameters)key.getRepresentation();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return new KeyParameter((byte[])key.getRepresentation());
        }

        throw new IllegalArgumentException("unknown generic key type");
    }
}