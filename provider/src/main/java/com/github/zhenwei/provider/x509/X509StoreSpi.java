package com.github.zhenwei.provider.x509;

import java.util.Collection;
import org.bouncycastle.util.Selector;
import org.bouncycastle.x509.X509StoreParameters;

public abstract class X509StoreSpi
{
    public abstract void engineInit(X509StoreParameters parameters);

    public abstract Collection engineGetMatches(Selector selector);
}