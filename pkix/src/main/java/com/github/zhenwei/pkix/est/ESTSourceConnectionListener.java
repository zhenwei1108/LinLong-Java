package com.github.zhenwei.pkix.est;

import java.io.IOException;
import org.bouncycastle.est.ESTRequest;
import org.bouncycastle.est.Source;

/**
 * ESTSourceConnectionListener is called when the source is
 * is connected to the remote end point but no application
 * data has been sent.
 */
public interface ESTSourceConnectionListener<T, I>
{
    ESTRequest onConnection(Source<T> source, ESTRequest request)
        throws IOException;
}