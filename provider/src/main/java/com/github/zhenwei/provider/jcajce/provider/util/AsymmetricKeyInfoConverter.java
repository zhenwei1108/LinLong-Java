package com.github.zhenwei.provider.jcajce.provider.util;


import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import pkcs.PrivateKeyInfo;

public interface AsymmetricKeyInfoConverter
{
    PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException;

    PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException;
}