package com.github.zhenwei.core.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.params.GOST3410ValidationParameters;

public class GOST3410Parameters
   implements CipherParameters
{
    private BigInteger              p;
    private BigInteger              q;
    private BigInteger              a;
    private GOST3410ValidationParameters validation;

    public GOST3410Parameters(
        BigInteger  p,
        BigInteger  q,
        BigInteger  a)
    {
        this.p = p;
        this.q = q;
        this.a = a;
    }

    public GOST3410Parameters(
        BigInteger              p,
        BigInteger              q,
        BigInteger              a,
        GOST3410ValidationParameters params)
    {
        this.a = a;
        this.p = p;
        this.q = q;
        this.validation = params;
    }

    public BigInteger getP()
    {
        return p;
    }

    public BigInteger getQ()
    {
        return q;
    }

    public BigInteger getA()
    {
        return a;
    }

    public GOST3410ValidationParameters getValidationParameters()
    {
        return validation;
    }

    public int hashCode()
    {
        return p.hashCode() ^ q.hashCode() ^ a.hashCode();
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof org.bouncycastle.crypto.params.GOST3410Parameters))
        {
            return false;
        }

        org.bouncycastle.crypto.params.GOST3410Parameters pm = (org.bouncycastle.crypto.params.GOST3410Parameters)obj;

        return (pm.getP().equals(p) && pm.getQ().equals(q) && pm.getA().equals(a));
    }
}