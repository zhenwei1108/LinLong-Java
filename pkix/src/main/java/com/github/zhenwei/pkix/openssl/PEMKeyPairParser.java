package com.github.zhenwei.pkix.openssl;

import java.io.IOException;
import org.bouncycastle.openssl.PEMKeyPair;

interface PEMKeyPairParser
{
    PEMKeyPair parse(byte[] encoding)
        throws IOException;
}