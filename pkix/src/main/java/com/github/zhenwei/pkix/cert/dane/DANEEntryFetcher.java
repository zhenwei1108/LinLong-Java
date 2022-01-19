package com.github.zhenwei.pkix.cert.dane;

import java.util.List;
import org.bouncycastle.cert.dane.DANEException;

public interface DANEEntryFetcher
{
    List getEntries() throws DANEException;
}