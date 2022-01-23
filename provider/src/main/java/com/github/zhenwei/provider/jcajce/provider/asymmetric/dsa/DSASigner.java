package com.github.zhenwei.provider.jcajce.provider.asymmetric.dsa;


import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import  X509ObjectIdentifiers;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.util.DigestFactory;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
 
import  NullDigest;
import  RIPEMD160Digest;
 
import DSAEncoding;
import HMacDSAKCalculator;
import StandardDSAEncoding;



public class DSASigner
    extends SignatureSpi
    implements PKCSObjectIdentifiers, X509ObjectIdentifiers
{
    private Digest                  digest;
    private DSAExt                  signer;
    private DSAEncoding             encoding = StandardDSAEncoding.INSTANCE;
    private SecureRandom            random;

    protected DSASigner(
        Digest digest,
        DSAExt signer)
    {
        this.digest = digest;
        this.signer = signer;
    }

    protected void engineInitVerify(
        PublicKey   publicKey)
        throws InvalidKeyException
    {
        CipherParameters param = DSAUtil.generatePublicKeyParameter(publicKey);

        digest.reset();
        signer.init(false, param);
    }

    protected void engineInitSign(
        PrivateKey      privateKey,
        SecureRandom    random)
        throws InvalidKeyException
    {
        this.random = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(
        PrivateKey  privateKey)
        throws InvalidKeyException
    {
        CipherParameters    param = DSAUtil.generatePrivateKeyParameter(privateKey);

        if (random != null)
        {
            param = new ParametersWithRandom(param, random);
        }

        digest.reset();
        signer.init(true, param);
    }

    protected void engineUpdate(
        byte    b)
        throws SignatureException
    {
        digest.update(b);
    }

    protected void engineUpdate(
        byte[]  b,
        int     off,
        int     len) 
        throws SignatureException
    {
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        byte[]  hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        try
        {
            BigInteger[] sig = signer.generateSignature(hash);

            return encoding.encode(signer.getOrder(), sig[0], sig[1]);
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(
        byte[]  sigBytes) 
        throws SignatureException
    {
        byte[]  hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        BigInteger[] sig;

        try
        {
            sig = encoding.decode(signer.getOrder(), sigBytes);
        }
        catch (Exception e)
        {
            throw new SignatureException("error decoding signature bytes.");
        }

        return signer.verifySignature(hash, sig[0], sig[1]);
    }

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec)
     */
    protected void engineSetParameter(
        String  param,
        Object  value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(
        String      param)
    {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    static public class stdDSA
        extends dsa.DSASigner
    {
        public stdDSA()
        {
            super(DigestFactory.createSHA1(), new DSASigner());
        }
    }

    static public class detDSA
        extends dsa.DSASigner
    {
        public detDSA()
        {
            super(DigestFactory.createSHA1(), new DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA1())));
        }
    }

    static public class dsaRMD160
        extends dsa.DSASigner
    {
        public dsaRMD160()
        {
            super(new RIPEMD160Digest(), new DSASigner());
        }
    }

    static public class dsa224
        extends dsa.DSASigner
    {
        public dsa224()
        {
            super(DigestFactory.createSHA224(), new DSASigner());
        }
    }

    static public class detDSA224
        extends dsa.DSASigner
    {
        public detDSA224()
        {
            super(DigestFactory.createSHA224(), new DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA224())));
        }
    }

    static public class dsa256
        extends dsa.DSASigner
    {
        public dsa256()
        {
            super(DigestFactory.createSHA256(), new DSASigner());
        }
    }

    static public class detDSA256
        extends dsa.DSASigner
    {
        public detDSA256()
        {
            super(DigestFactory.createSHA256(), new DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA256())));
        }
    }

    static public class dsa384
        extends dsa.DSASigner
    {
        public dsa384()
        {
            super(DigestFactory.createSHA384(), new DSASigner());
        }
    }

    static public class detDSA384
        extends dsa.DSASigner
    {
        public detDSA384()
        {
            super(DigestFactory.createSHA384(), new DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA384())));
        }
    }

    static public class dsa512
        extends dsa.DSASigner
    {
        public dsa512()
        {
            super(DigestFactory.createSHA512(), new DSASigner());
        }
    }

    static public class detDSA512
        extends dsa.DSASigner
    {
        public detDSA512()
        {
            super(DigestFactory.createSHA512(), new DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA512())));
        }
    }

    static public class dsaSha3_224
        extends dsa.DSASigner
    {
        public dsaSha3_224()
        {
            super(DigestFactory.createSHA3_224(), new DSASigner());
        }
    }

    static public class detDSASha3_224
        extends dsa.DSASigner
    {
        public detDSASha3_224()
        {
            super(DigestFactory.createSHA3_224(), new DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_224())));
        }
    }

    static public class dsaSha3_256
        extends dsa.DSASigner
    {
        public dsaSha3_256()
        {
            super(DigestFactory.createSHA3_256(), new DSASigner());
        }
    }

    static public class detDSASha3_256
        extends dsa.DSASigner
    {
        public detDSASha3_256()
        {
            super(DigestFactory.createSHA3_256(), new DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_256())));
        }
    }

    static public class dsaSha3_384
        extends dsa.DSASigner
    {
        public dsaSha3_384()
        {
            super(DigestFactory.createSHA3_384(), new DSASigner());
        }
    }

    static public class detDSASha3_384
        extends dsa.DSASigner
    {
        public detDSASha3_384()
        {
            super(DigestFactory.createSHA3_384(), new DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_384())));
        }
    }

    static public class dsaSha3_512
        extends dsa.DSASigner
    {
        public dsaSha3_512()
        {
            super(DigestFactory.createSHA3_512(), new DSASigner());
        }
    }

    static public class detDSASha3_512
        extends dsa.DSASigner
    {
        public detDSASha3_512()
        {
            super(DigestFactory.createSHA3_512(), new DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_512())));
        }
    }

    static public class noneDSA
        extends dsa.DSASigner
    {
        public noneDSA()
        {
            super(new NullDigest(), new DSASigner());
        }
    }
}