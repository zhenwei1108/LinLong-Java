package com.github.zhenwei.core.crypto.engines;

import com.github.zhenwei.core.crypto.BlockCipher;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.DataLengthException;
import com.github.zhenwei.core.crypto.OutputLengthException;
import com.github.zhenwei.core.crypto.params.KeyParameter;
import com.github.zhenwei.core.util.Integers;
import com.github.zhenwei.core.util.Pack;


/**
 * A Noekeon engine, using direct-key mode.
 */
public class NoekeonEngine
    implements BlockCipher
{
    // Block and key size, as well as the amount of rounds.
    private static final int SIZE = 16;

    // Used in decryption
    private static final byte[] roundConstants = { (byte)0x80, 0x1b, 0x36, 0x6c, (byte)0xd8, (byte)0xab, 0x4d,
        (byte)0x9a, 0x2f, 0x5e, (byte)0xbc, 0x63, (byte)0xc6, (byte)0x97, 0x35, 0x6a, (byte)0xd4 };

    private final int[] k = new int[4];

    private boolean _initialised, _forEncryption;

    /**
     * Create an instance of the Noekeon encryption algorithm and set some defaults
     */
    public NoekeonEngine()
    {
        _initialised = false;
    }

    public String getAlgorithmName()
    {
        return "Noekeon";
    }

    public int getBlockSize()
    {
        return SIZE;
    }

    /**
     * initialise
     *
     * @param forEncryption
     *            whether or not we are for encryption.
     * @param params
     *            the parameters required to set up the cipher.
     * @exception IllegalArgumentException
     *                if the params argument is inappropriate.
     */
    public void init(boolean forEncryption, CipherParameters params)
    {
        if (!(params instanceof KeyParameter))
        {
            throw new IllegalArgumentException(
                "invalid parameter passed to Noekeon init - " + params.getClass().getName());
        }

        KeyParameter p = (KeyParameter)params;
        byte[] key = p.getKey();
        if (key.length != 16)
        {
            throw new IllegalArgumentException("Key length not 128 bits.");
        }

        Pack.bigEndianToInt(key, 0, k, 0, 4);

        if (!forEncryption)
        {
            // theta(k, new int[]{ 0x00, 0x00, 0x00, 0x00 });
            {
                int a0 = k[0], a1 = k[1], a2 = k[2], a3 = k[3];

                int t02 = a0 ^ a2;
                t02 ^= Integers.rotateLeft(t02, 8) ^ Integers.rotateLeft(t02, 24);

                int t13 = a1 ^ a3;
                t13 ^= Integers.rotateLeft(t13, 8) ^ Integers.rotateLeft(t13, 24);

                a0 ^= t13;
                a1 ^= t02;
                a2 ^= t13;
                a3 ^= t02;

                k[0] = a0; k[1] = a1; k[2] = a2; k[3] = a3;
            }
        }

        this._forEncryption = forEncryption;
        this._initialised = true;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
    {
        if (!_initialised)
        {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        }
        if (inOff > in.length - SIZE)
        {
            throw new DataLengthException("input buffer too short");
        }
        if (outOff > out.length - SIZE)
        {
            throw new OutputLengthException("output buffer too short");
        }

        return _forEncryption ? encryptBlock(in, inOff, out, outOff) : decryptBlock(in, inOff, out, outOff);
    }

    public void reset()
    {
    }

    private int encryptBlock(byte[] in, int inOff, byte[] out, int outOff)
    {
        int a0 = Pack.bigEndianToInt(in, inOff);
        int a1 = Pack.bigEndianToInt(in, inOff + 4);
        int a2 = Pack.bigEndianToInt(in, inOff + 8);
        int a3 = Pack.bigEndianToInt(in, inOff + 12);

        int k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];

        int round = 0;
        for (;;)
        {
            a0 ^= roundConstants[round] & 0xFF;

            // theta(a, k);
            {
                int t02 = a0 ^ a2;
                t02 ^= Integers.rotateLeft(t02, 8) ^ Integers.rotateLeft(t02, 24);

                a0 ^= k0;
                a1 ^= k1;
                a2 ^= k2;
                a3 ^= k3;

                int t13 = a1 ^ a3;
                t13 ^= Integers.rotateLeft(t13, 8) ^ Integers.rotateLeft(t13, 24);

                a0 ^= t13;
                a1 ^= t02;
                a2 ^= t13;
                a3 ^= t02;
            }

            if (++round > SIZE)
            {
                break;
            }

            // pi1(a);
            {
                a1 = Integers.rotateLeft(a1, 1);
                a2 = Integers.rotateLeft(a2, 5);
                a3 = Integers.rotateLeft(a3, 2);
            }

            // gamma(a);
            {
                int t = a3;
                a1 ^= a3 | a2;
                a3 = a0 ^ (a2 & ~a1);

                a2 = t ^ ~a1 ^ a2 ^ a3;

                a1 ^= a3 | a2;
                a0 = t ^ (a2 & a1);
            }

            // pi2(a);
            {
                a1 = Integers.rotateLeft(a1, 31);
                a2 = Integers.rotateLeft(a2, 27);
                a3 = Integers.rotateLeft(a3, 30);
            }
        }

        Pack.intToBigEndian(a0, out, outOff);
        Pack.intToBigEndian(a1, out, outOff + 4);
        Pack.intToBigEndian(a2, out, outOff + 8);
        Pack.intToBigEndian(a3, out, outOff + 12);

        return SIZE;
    }

    private int decryptBlock(byte[] in, int inOff, byte[] out, int outOff)
    {
        int a0 = Pack.bigEndianToInt(in, inOff);
        int a1 = Pack.bigEndianToInt(in, inOff + 4);
        int a2 = Pack.bigEndianToInt(in, inOff + 8);
        int a3 = Pack.bigEndianToInt(in, inOff + 12);

        int k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];

        int round = SIZE;
        for (;;)
        {
            // theta(a, k);
            {
                int t02 = a0 ^ a2;
                t02 ^= Integers.rotateLeft(t02, 8) ^ Integers.rotateLeft(t02, 24);

                a0 ^= k0;
                a1 ^= k1;
                a2 ^= k2;
                a3 ^= k3;

                int t13 = a1 ^ a3;
                t13 ^= Integers.rotateLeft(t13, 8) ^ Integers.rotateLeft(t13, 24);

                a0 ^= t13;
                a1 ^= t02;
                a2 ^= t13;
                a3 ^= t02;
            }

            a0 ^= roundConstants[round] & 0xFF;

            if (--round < 0)
            {
                break;
            }

            // pi1(a);
            {
                a1 = Integers.rotateLeft(a1, 1);
                a2 = Integers.rotateLeft(a2, 5);
                a3 = Integers.rotateLeft(a3, 2);
            }

            // gamma(a);
            {
                int t = a3;
                a1 ^= a3 | a2;
                a3 = a0 ^ (a2 & ~a1);

                a2 = t ^ ~a1 ^ a2 ^ a3;

                a1 ^= a3 | a2;
                a0 = t ^ (a2 & a1);
            }

            // pi2(a);
            {
                a1 = Integers.rotateLeft(a1, 31);
                a2 = Integers.rotateLeft(a2, 27);
                a3 = Integers.rotateLeft(a3, 30);
            }
        }

        Pack.intToBigEndian(a0, out, outOff);
        Pack.intToBigEndian(a1, out, outOff + 4);
        Pack.intToBigEndian(a2, out, outOff + 8);
        Pack.intToBigEndian(a3, out, outOff + 12);

        return SIZE;
    }
}