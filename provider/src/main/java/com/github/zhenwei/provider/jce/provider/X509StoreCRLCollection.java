package com.github.zhenwei.provider.jce.provider;

import com.github.zhenwei.core.util.CollectionStore;
import com.github.zhenwei.core.util.Selector;
import com.github.zhenwei.provider.x509.X509CollectionStoreParameters;
import com.github.zhenwei.provider.x509.X509StoreParameters;
import com.github.zhenwei.provider.x509.X509StoreSpi;
import java.util.Collection;

public class X509StoreCRLCollection
    extends X509StoreSpi {

  private CollectionStore _store;

  public X509StoreCRLCollection() {
  }

  public void engineInit(X509StoreParameters params) {
    if (!(params instanceof X509CollectionStoreParameters)) {
      throw new IllegalArgumentException(params.toString());
    }

    _store = new CollectionStore(((X509CollectionStoreParameters) params).getCollection());
  }

  public Collection engineGetMatches(Selector selector) {
    return _store.getMatches(selector);
  }
}