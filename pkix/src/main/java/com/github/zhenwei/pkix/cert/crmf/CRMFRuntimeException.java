package com.github.zhenwei.pkix.cert.crmf;

public class CRMFRuntimeException
    extends RuntimeException
{
    private Throwable cause;

    public CRMFRuntimeException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}