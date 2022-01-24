package com.github.zhenwei.core.crypto;

import java.io.IOException;
import java.io.InputStream;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;

public interface KeyParser
{
    AsymmetricKeyParameter readKey(InputStream stream)
        throws IOException;
}