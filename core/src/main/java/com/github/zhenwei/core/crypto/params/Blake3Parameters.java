package com.github.zhenwei.core.crypto.params;


import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.util.Arrays;

/**
 * Blake3 Parameters.
 */
public class Blake3Parameters
        implements CipherParameters
{
    /**
     * The key length.
     */
    private static final int KEYLEN = 32;

    /**
     * The key.
     */
    private byte[] theKey;

    /**
     * The context.
     */
    private byte[] theContext;

    /**
     * Create a key parameter.
     * @param pContext the context
     * @return the parameter
     */
    public static org.bouncycastle.crypto.params.Blake3Parameters context(final byte[] pContext)
    {
        if (pContext == null)
        {
            throw new IllegalArgumentException("Invalid context");
        }
        final org.bouncycastle.crypto.params.Blake3Parameters myParams = new org.bouncycastle.crypto.params.Blake3Parameters();
        myParams.theContext = Arrays.clone(pContext);
        return myParams;
    }

    /**
     * Create a key parameter.
     * @param pKey the key
     * @return the parameter
     */
    public static org.bouncycastle.crypto.params.Blake3Parameters key(final byte[] pKey)
    {
        if (pKey == null || pKey.length != KEYLEN)
        {
            throw new IllegalArgumentException("Invalid keyLength");
        }
        final org.bouncycastle.crypto.params.Blake3Parameters myParams = new org.bouncycastle.crypto.params.Blake3Parameters();
        myParams.theKey = Arrays.clone(pKey);
        return myParams;
    }

    /**
     * Obtain the key.
     * @return the key
     */
    public byte[] getKey()
    {
        return Arrays.clone(theKey);
    }

    /**
     * Clear the key bytes.
      */
    public void clearKey()
    {
        Arrays.fill(theKey, (byte) 0);
    }

    /**
     * Obtain the salt.
     * @return the salt
     */
    public byte[] getContext()
    {
        return Arrays.clone(theContext);
    }
}