package com.github.zhenwei.provider.jce.provider;

import java.util.Collection;
import org.bouncycastle.X509CollectionStoreParameters;
import org.bouncycastle.X509StoreParameters;
import org.bouncycastle.util.CollectionStore;

import org.bouncycastle.x509.X509StoreSpi;

public class X509StoreCRLCollection
    extends X509StoreSpi
{
    private CollectionStore _store;

    public X509StoreCRLCollection()
    {
    }

    public void engineInit(X509StoreParameters params)
    {
        if (!(params instanceof X509CollectionStoreParameters))
        {
            throw new IllegalArgumentException(params.toString());
        }

        _store = new CollectionStore(((X509CollectionStoreParameters)params).getCollection());
    }

    public Collection engineGetMatches(Selector selector)
    {
        return _store.getMatches(selector);
    }
}