package com.github.zhenwei.pkix.cert.dane;

import org.bouncycastle.cert.dane.DANEEntryFetcherFactory;
import org.bouncycastle.cert.dane.DANEEntryStore;
import org.bouncycastle.cert.dane.DANEException;

/**
 * Builder for the DANECertificateStore.
 */
public class DANEEntryStoreBuilder
{
    private final DANEEntryFetcherFactory daneEntryFetcher;

    public DANEEntryStoreBuilder(DANEEntryFetcherFactory daneEntryFetcher)
    {
        this.daneEntryFetcher = daneEntryFetcher;
    }

    /**
     * Build a DANECertificateStore from the provided domainName details.
     *
     * @param domainName the domain name to look up the _smimecert entries in.
     * @return a Store of DANEEntry representing the _smimecert entries containing certificates.
     * @throws DANEException in the case of a DNS issue or encoding issue with a DNS record.
     */
    public DANEEntryStore build(String domainName)
        throws DANEException
    {
        return new DANEEntryStore(daneEntryFetcher.build(domainName).getEntries());
    }
}