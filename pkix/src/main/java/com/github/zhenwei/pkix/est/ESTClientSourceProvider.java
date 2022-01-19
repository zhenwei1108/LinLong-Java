package com.github.zhenwei.pkix.est;

import java.io.IOException;
import org.bouncycastle.est.Source;

/**
 * ESTClientSourceProvider, implementations of this are expected to return a source.
 */
public interface ESTClientSourceProvider
{
    Source makeSource(String host, int port)
        throws IOException;
}