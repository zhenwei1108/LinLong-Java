package com.github.zhenwei.core.pqc.crypto.lms;


import java.util.HashMap;
import java.util.Map;


public class LMOtsParameters
{
    public static final int reserved = 0;
    public static final org.bouncycastle.pqc.crypto.lms.LMOtsParameters sha256_n32_w1 = new org.bouncycastle.pqc.crypto.lms.LMOtsParameters(1, 32, 1, 265, 7, 8516, NISTObjectIdentifiers.id_sha256);
    public static final org.bouncycastle.pqc.crypto.lms.LMOtsParameters sha256_n32_w2 = new org.bouncycastle.pqc.crypto.lms.LMOtsParameters(2, 32, 2, 133, 6, 4292, NISTObjectIdentifiers.id_sha256);
    public static final org.bouncycastle.pqc.crypto.lms.LMOtsParameters sha256_n32_w4 = new org.bouncycastle.pqc.crypto.lms.LMOtsParameters(3, 32, 4, 67, 4, 2180, NISTObjectIdentifiers.id_sha256);
    public static final org.bouncycastle.pqc.crypto.lms.LMOtsParameters sha256_n32_w8 = new org.bouncycastle.pqc.crypto.lms.LMOtsParameters(4, 32, 8, 34, 0, 1124, NISTObjectIdentifiers.id_sha256);

    private static final Map<Object, org.bouncycastle.pqc.crypto.lms.LMOtsParameters> suppliers = new HashMap<Object, org.bouncycastle.pqc.crypto.lms.LMOtsParameters>()
    {
        {
            put(sha256_n32_w1.type, sha256_n32_w1);
            put(sha256_n32_w2.type, sha256_n32_w2);
            put(sha256_n32_w4.type, sha256_n32_w4);
            put(sha256_n32_w8.type, sha256_n32_w8);
        }
    };

    private final int type;
    private final int n;
    private final int w;
    private final int p;
    private final int ls;
    private final int sigLen;
    private final ASN1ObjectIdentifier digestOID;

    protected LMOtsParameters(int type, int n, int w, int p, int ls, int sigLen, ASN1ObjectIdentifier digestOID)
    {
        this.type = type;
        this.n = n;
        this.w = w;
        this.p = p;
        this.ls = ls;
        this.sigLen = sigLen;
        this.digestOID = digestOID;
    }

    public int getType()
    {
        return type;
    }

    public int getN()
    {
        return n;
    }

    public int getW()
    {
        return w;
    }

    public int getP()
    {
        return p;
    }

    public int getLs()
    {
        return ls;
    }

    public int getSigLen()
    {
        return sigLen;
    }

    public ASN1ObjectIdentifier getDigestOID()
    {
        return digestOID;
    }

    public static org.bouncycastle.pqc.crypto.lms.LMOtsParameters getParametersForType(int type)
    {
        return suppliers.get(type);
    }
}