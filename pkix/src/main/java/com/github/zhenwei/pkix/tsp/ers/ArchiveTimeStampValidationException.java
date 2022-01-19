package com.github.zhenwei.pkix.tsp.ers;

import org.bouncycastle.tsp.ers.ERSException;

/**
 * Exception thrown if an Archive TimeStamp according to RFC4998 fails to containsHashValue.
 * <p>
 * {@see <a href="https://tools.ietf.org/html/rfc4998">RFC4998</a>}
 */
public class ArchiveTimeStampValidationException
    extends ERSException
{
    public ArchiveTimeStampValidationException(final String message)
    {
        super(message);
    }
}