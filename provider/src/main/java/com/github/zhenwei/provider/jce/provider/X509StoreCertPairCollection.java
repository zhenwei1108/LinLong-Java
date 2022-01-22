package com.github.zhenwei.provider.jce.provider;

import com.github.zhenwei.core.util.CollectionStore;
import java.util.Collection;
import org.bouncycastle.X509CollectionStoreParameters;
import org.bouncycastle.X509StoreParameters;
import org.bouncycastle.X509StoreSpi;



/**
 * This class is a collection based Bouncy Castle
 * {@link org.bouncycastle.X509Store} SPI implementation for certificate
 * pairs.
 *
 * @see org.bouncycastle.X509Store
 * @see org.bouncycastle.X509CertificatePair
 */
public class X509StoreCertPairCollection extends X509StoreSpi
{

    private CollectionStore _store;

    public X509StoreCertPairCollection()
    {
    }

    /**
     * Initializes this store.
     *
     * @param params The {@link X509CollectionStoreParameters}s for this store.
     * @throws IllegalArgumentException if <code>params</code> is no instance of
     *                                  <code>X509CollectionStoreParameters</code>.
     */
    public void engineInit(X509StoreParameters params)
    {
        if (!(params instanceof X509CollectionStoreParameters))
        {
            throw new IllegalArgumentException(
                "Initialization parameters must be an instance of "
                    + X509CollectionStoreParameters.class.getName()
                    + ".");
        }

        _store = new CollectionStore(((X509CollectionStoreParameters)params)
            .getCollection());
    }

    /**
     * Returns a colelction of certificate pairs which match the given
     * <code>selector</code>.
     * <p>
     * The returned collection contains
     * {@link org.bouncycastle.X509CertificatePair}s. The selector must be
     * a {@link org.bouncycastle.X509CertPairStoreSelector} to select
     * certificate pairs.
     * </p>
     * @return A collection with matching certificate pairs.
     */
    public Collection engineGetMatches(Selector selector)
    {
        return _store.getMatches(selector);
    }
}