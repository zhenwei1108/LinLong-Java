package com.github.zhenwei.provider.jcajce.provider.mceliece;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.X509ObjectIdentifiers;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.params.ParametersWithRandom;
import com.github.zhenwei.core.pqc.crypto.mceliece.McElieceCipher;
import com.github.zhenwei.core.pqc.crypto.mceliece.McElieceKeyParameters;
import com.github.zhenwei.provider.jcajce.provider.util.AsymmetricBlockCipher;

public class McEliecePKCSCipherSpi
    extends AsymmetricBlockCipher
    implements PKCSObjectIdentifiers, X509ObjectIdentifiers
{
    private McElieceCipher cipher;

    public McEliecePKCSCipherSpi(McElieceCipher cipher)
    {
        this.cipher = cipher;
    }

    protected void initCipherEncrypt(Key key, AlgorithmParameterSpec params,
                                     SecureRandom sr)
        throws InvalidKeyException,
        InvalidAlgorithmParameterException
    {

        CipherParameters param;
        param = McElieceKeysToParams.generatePublicKeyParameter((PublicKey)key);

        param = new ParametersWithRandom(param, sr);
        cipher.init(true, param);
        this.maxPlainTextSize = cipher.maxPlainTextSize;
        this.cipherTextSize = cipher.cipherTextSize;
    }

    protected void initCipherDecrypt(Key key, AlgorithmParameterSpec params)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        CipherParameters param;
        param = McElieceKeysToParams.generatePrivateKeyParameter((PrivateKey)key);

        cipher.init(false, param);
        this.maxPlainTextSize = cipher.maxPlainTextSize;
        this.cipherTextSize = cipher.cipherTextSize;
    }

    protected byte[] messageEncrypt(byte[] input)
        throws IllegalBlockSizeException, BadPaddingException
    {
        byte[] output = null;
        try
        {
            output = cipher.messageEncrypt(input);
        }
        catch (Exception e)
        {
            throw new IllegalBlockSizeException(e.getMessage());
        }
        return output;
    }

    protected byte[] messageDecrypt(byte[] input)
        throws IllegalBlockSizeException, BadPaddingException
    {
        byte[] output = null;
        try
        {
            output = cipher.messageDecrypt(input);
        }
        catch (Exception e)
        {
            throw new IllegalBlockSizeException(e.getMessage());
        }
        return output;
    }

    public String getName()
    {
        return "McEliecePKCS";
    }

    public int getKeySize(Key key)
        throws InvalidKeyException
    {
        McElieceKeyParameters mcElieceKeyParameters;
        if (key instanceof PublicKey)
        {
            mcElieceKeyParameters = (McElieceKeyParameters)McElieceKeysToParams.generatePublicKeyParameter((PublicKey)key);
        }
        else
        {
            mcElieceKeyParameters = (McElieceKeyParameters)McElieceKeysToParams.generatePrivateKeyParameter((PrivateKey)key);

        }


        return cipher.getKeySize(mcElieceKeyParameters);
    }

    static public class McEliecePKCS
        extends McEliecePKCSCipherSpi
    {
        public McEliecePKCS()
        {
            super(new McElieceCipher());
        }
    }
}