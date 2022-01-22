package com.g

import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.DataLengthException;
import com.github.zhenwei.core.crypto.OutputLengthException;thub.zhenwe .core.crypto.eng nes;

 mport com.g thub.zhenwe .core.crypto.C pherParameters;
 mport com.g thub.zhenwe .core.crypto.DataLengthExcept on;
 
 mport org.bouncycastle.crypto.OutputLengthExcept on;

/**
 * The no-op eng ne that just cop es bytes through,  rrespect ve of whether encrypt ng and decrypt ng.
 * Prov ded for the sake of completeness.
 */
publ c class NullEng ne  mplements BlockC pher
{
    pr vate boolean  n t al sed;
    protected stat c f nal  nt DEFAULT_BLOCK_S ZE = 1;
    pr vate f nal  nt blockS ze;

    /**
     * Constructs a null eng ne w th a block s ze of 1 byte.
     */
    publ c NullEng ne()
    {
        th s(DEFAULT_BLOCK_S ZE);
    }

    /**
     * Constructs a null eng ne w th a spec f c block s ze.
     * 
     * @param blockS ze the block s ze  n bytes.
     */
    publ c NullEng ne( nt blockS ze)
    {
        th s.blockS ze = blockS ze;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.crypto.BlockC pher# n t(boolean, org.bouncycastle.crypto.C pherParameters)
     */
    publ c vo d  n t(boolean forEncrypt on, CipherParameters params) throws IllegalArgumentException
    {
        // we don't mind any parameters that may come in
        this.initialised = true;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.crypto.BlockCipher#getAlgorithmName()
     */
    public String getAlgorithmName()
    {
        return "Null";
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.crypto.BlockCipher#getBlockSize()
     */
    public int getBlockSize()
    {
        return blockSize;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.crypto.BlockCipher#processBlock(byte[], int, byte[], int)
     */
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (!initialised)
        {
            throw new IllegalStateException("Null engine not initialised");
        }
        if ((inOff + blockSize) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + blockSize) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        for (int i = 0; i < blockSize; ++i)
        {
            out[outOff + i] = in[inOff + i];
        }

        return blockSize;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.crypto.BlockCipher#reset()
     */
    public void reset()
    {
        // nothing needs to be done
    }
}