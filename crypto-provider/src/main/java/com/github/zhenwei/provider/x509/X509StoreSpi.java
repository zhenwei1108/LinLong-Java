package com.github.zhenwei.provider.x509;

import com.github.zhenwei.core.util.Selector;
import java.util.Collection;

public abstract class X509StoreSpi {

  public abstract void engineInit(X509StoreParameters parameters);

  public abstract Collection engineGetMatches(Selector selector);
}