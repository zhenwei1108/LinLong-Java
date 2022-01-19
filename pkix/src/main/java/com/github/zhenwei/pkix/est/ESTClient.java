package com.github.zhenwei.pkix.est;

import java.io.IOException;
import org.bouncycastle.est.ESTRequest;
import org.bouncycastle.est.ESTResponse;

/**
 * ESTClient implement connection to the server.
 * <p>
 * Implementations should be aware that they are responsible for
 * satisfying <a href="https://tools.ietf.org/html/rfc7030#section-3.3">RFC7030 3.3 - TLS Layer</a>
 * including SRP modes.
 */
public interface ESTClient
{
    public ESTResponse doRequest(ESTRequest c)
        throws IOException;
}