package com.github.zhenwei.pkix.dvcs;

import org.bouncycastle.dvcs.DVCSException;

/**
 * Exception thrown when failed to initialize some DVCS-related staff.
 */
public class DVCSConstructionException
    extends DVCSException
{
    private static final long serialVersionUID = 660035299653583980L;

    public DVCSConstructionException(String message)
    {
        super(message);
    }

    public DVCSConstructionException(String message, Throwable cause)
    {
        super(message, cause);
    }
}