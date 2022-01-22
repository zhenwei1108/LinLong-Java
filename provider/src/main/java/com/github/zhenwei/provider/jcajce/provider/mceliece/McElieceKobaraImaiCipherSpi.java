package com.github.zhenwei.provider.jcajce.provider.mceliece;


import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;


import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ParametersWithRandom;

import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKobaraImaiCipher;
import org.bouncycastle.pqc.jcajce.provider.util.AsymmetricHybridCipher;


public class McElieceKobaraImaiCipherSpi
    extends AsymmetricHybridCipher
    implements PKCSObjectIdentifiers, X509ObjectIdentifiers
{

    // TODO digest needed?
    private Digest digest;
    private McElieceKobaraImaiCipher cipher;

    /**
     * buffer to store the input data
     */
    private ByteArrayOutputStream buf = new ByteArrayOutputStream();


    public McElieceKobaraImaiCipherSpi()
    {
        buf = new ByteArrayOutputStream();
    }

    protected McElieceKobaraImaiCipherSpi(Digest digest, McElieceKobaraImaiCipher cipher)
    {
        this.digest = digest;
        this.cipher = cipher;
        buf = new ByteArrayOutputStream();
    }

    /**
     * Continue a multiple-part encryption or decryption operation.
     *
     * @param input byte array containing the next part of the input
     * @param inOff index in the array where the input starts
     * @param inLen length of the input
     * @return the processed byte array.
     */
    public byte[] update(byte[] input, int inOff, int inLen)
    {
        buf.write(input, inOff, inLen);
        return new byte[0];
    }


    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted, depending on
     * how this cipher was initialized.
     *
     * @param input the input buffer
     * @param inOff the offset in input where the input starts
     * @param inLen the input length
     * @return the new buffer with the result
     * @throws BadPaddingException if this cipher is in decryption mode, and (un)padding has
     * been requested, but the decrypted data is not bounded by
     * the appropriate padding bytes
     */
    public byte[] doFinal(byte[] input, int inOff, int inLen)
        throws BadPaddingException
    {
        update(input, inOff, inLen);
        if (opMode == ENCRYPT_MODE)
        {
            return cipher.messageEncrypt(this.pad());
        }
        else if (opMode == DECRYPT_MODE)
        {
            try
            {
                byte[] inputOfDecr = buf.toByteArray();
                buf.reset();

                return unpad(cipher.messageDecrypt(inputOfDecr));
            }
            catch (InvalidCipherTextException e)
            {
                throw new BadPaddingException(e.getMessage());
            }
        }
        else
        {
            throw new IllegalStateException("unknown mode in doFinal");
        }
    }

    protected int encryptOutputSize(int inLen)
    {
        return 0;
    }

    protected int decryptOutputSize(int inLen)
    {
        return 0;
    }

    protected void initCipherEncrypt(Key key, AlgorithmParameterSpec params,
                                     SecureRandom sr)
        throws InvalidKeyException,
        InvalidAlgorithmParameterException
    {

        buf.reset();
        CipherParameters param;
        param = McElieceCCA2KeysToParams.generatePublicKeyParameter((PublicKey)key);

        param = new ParametersWithRandom(param, sr);
        digest.reset();
        cipher.init(true, param);
    }

    protected void initCipherDecrypt(Key key, AlgorithmParameterSpec params)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {

        buf.reset();
        CipherParameters param;
        param = McElieceCCA2KeysToParams.generatePrivateKeyParameter((PrivateKey)key);

        digest.reset();
        cipher.init(false, param);
    }

    public String getName()
    {
        return "McElieceKobaraImaiCipher";
    }

    public int getKeySize(Key key)
        throws InvalidKeyException
    {
        McElieceCCA2KeyParameters mcElieceCCA2KeyParameters;
        if (key instanceof PublicKey)
        {
            mcElieceCCA2KeyParameters = (McElieceCCA2KeyParameters)McElieceCCA2KeysToParams.generatePublicKeyParameter((PublicKey)key);
            return cipher.getKeySize(mcElieceCCA2KeyParameters);
        }
        else if (key instanceof PrivateKey)
        {
            mcElieceCCA2KeyParameters = (McElieceCCA2KeyParameters)McElieceCCA2KeysToParams.generatePrivateKeyParameter((PrivateKey)key);
            return cipher.getKeySize(mcElieceCCA2KeyParameters);
        }
        else
        {
            throw new InvalidKeyException();
        }


    }

    /**
     * Pad and return the message stored in the message buffer.
     *
     * @return the padded message
     */
    private byte[] pad()
    {
        buf.write(0x01);
        byte[] result = buf.toByteArray();
        buf.reset();
        return result;
    }

    /**
     * Unpad a message.
     *
     * @param pmBytes the padded message
     * @return the message
     * @throws BadPaddingException if the padded message is invalid.
     */
    private byte[] unpad(byte[] pmBytes)
        throws BadPaddingException
    {
        // find first non-zero byte
        int index;
        for (index = pmBytes.length - 1; index >= 0 && pmBytes[index] == 0; index--)
        {
            ;
        }

        // check if padding byte is valid
        if (pmBytes[index] != 0x01)
        {
            throw new BadPaddingException("invalid ciphertext");
        }

        // extract and return message
        byte[] mBytes = new byte[index];
        System.arraycopy(pmBytes, 0, mBytes, 0, index);
        return mBytes;
    }

    static public class McElieceKobaraImai
        extends org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi
    {
        public McElieceKobaraImai()
        {
            super(DigestFactory.createSHA1(), new McElieceKobaraImaiCipher());
        }
    }

    static public class McElieceKobaraImai224
        extends org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi
    {
        public McElieceKobaraImai224()
        {
            super(DigestFactory.createSHA224(), new McElieceKobaraImaiCipher());
        }
    }

    static public class McElieceKobaraImai256
        extends org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi
    {
        public McElieceKobaraImai256()
        {
            super(DigestFactory.createSHA256(), new McElieceKobaraImaiCipher());
        }
    }

    static public class McElieceKobaraImai384
        extends org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi
    {
        public McElieceKobaraImai384()
        {
            super(DigestFactory.createSHA384(), new McElieceKobaraImaiCipher());
        }
    }

    static public class McElieceKobaraImai512
        extends org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi
    {
        public McElieceKobaraImai512()
        {
            super(DigestFactory.createSHA512(), new McElieceKobaraImaiCipher());
        }
    }


}