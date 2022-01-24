package com.github.zhenwei.core.pqc.crypto.ntru;

import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;

public class NTRUEncryptionKeyParameters
    extends AsymmetricKeyParameter
{
    final protected NTRUEncryptionParameters params;

    public NTRUEncryptionKeyParameters(boolean privateKey, NTRUEncryptionParameters params)
    {
        super(privateKey);
        this.params = params;
    }

    public NTRUEncryptionParameters getParameters()
    {
        return params;
    }
}