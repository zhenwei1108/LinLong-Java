package com.github.zhenwei.pkix.operator.bc;

import java.io.IOException;
import java.io.OutputStream;
import com.github.zhenwei.core.crypto.CryptoException;
import com.github.zhenwei.core.crypto.Signer;

public class BcSignerOutputStream
    extends OutputStream
{
    private Signer sig;

    BcSignerOutputStream(Signer sig)
    {
        this.sig = sig;
    }

    public void write(byte[] bytes, int off, int len)
        throws IOException
    {
        sig.update(bytes, off, len);
    }

    public void write(byte[] bytes)
        throws IOException
    {
        sig.update(bytes, 0, bytes.length);
    }

    public void write(int b)
        throws IOException
    {
        sig.update((byte)b);
    }

    byte[] getSignature()
        throws CryptoException
    {
        return sig.generateSignature();
    }

    boolean verify(byte[] expected)
    {
        return sig.verifySignature(expected);
    }
}