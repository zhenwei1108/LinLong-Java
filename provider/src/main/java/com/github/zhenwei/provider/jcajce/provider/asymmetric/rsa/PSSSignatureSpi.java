package com.github.zhenwei.provider.jcajce.provider.asymmetric.rsa;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.crypto.AsymmetricBlockCipher;
import com.github.zhenwei.core.crypto.CryptoException;
import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.engines.RSABlindedEngine;
import com.github.zhenwei.core.crypto.params.ParametersWithRandom;
import com.github.zhenwei.core.crypto.params.RSAKeyParameters;
import com.github.zhenwei.provider.jcajce.provider.util.DigestFactory;
import  com.github.zhenwei.provider.jcajce.util.BCJcaJceHelper;
import  com.github.zhenwei.provider.jcajce.util.JcaJceHelper;

public class PSSSignatureSpi
    extends SignatureSpi
{
    private final JcaJceHelper helper = new BCJcaJceHelper();

    private AlgorithmParameters engineParams;
    private PSSParameterSpec paramSpec;
    private PSSParameterSpec originalSpec;
    private AsymmetricBlockCipher signer;
    private Digest contentDigest;
    private Digest mgfDigest;
    private int saltLength;
    private byte trailer;
    private boolean isRaw;
    private RSAKeyParameters key;
    private SecureRandom random;

    private com.github.zhenwei.core.crypto.signers.PSSSigner pss;
    private boolean isInitState = true;

    private byte getTrailer(
        int trailerField)
    {
        if (trailerField == 1)
        {
            return com.github.zhenwei.core.crypto.signers.PSSSigner.TRAILER_IMPLICIT;
        }
        
        throw new IllegalArgumentException("unknown trailer field");
    }

    private void setupContentDigest()
    {
        if (isRaw)
        {
            this.contentDigest = new NullPssDigest(mgfDigest);
        }
        else
        {
            this.contentDigest = DigestFactory.getDigest(paramSpec.getDigestAlgorithm());
        }
    }

    // care - this constructor is actually used by outside organisations
    protected PSSSignatureSpi(
        AsymmetricBlockCipher signer,
        PSSParameterSpec paramSpecArg)
    {
        this(signer, paramSpecArg, false);
    }

    // care - this constructor is actually used by outside organisations
    protected PSSSignatureSpi(
        AsymmetricBlockCipher signer,
        PSSParameterSpec baseParamSpec,
        boolean isRaw)
    {
        this.signer = signer;
        this.originalSpec = baseParamSpec;
        
        if (baseParamSpec == null)
        {
            this.paramSpec = PSSParameterSpec.DEFAULT;
        }
        else
        {
            this.paramSpec = baseParamSpec;
        }

        if ("MGF1".equals(paramSpec.getMGFAlgorithm()))
        {
            this.mgfDigest = DigestFactory.getDigest(paramSpec.getDigestAlgorithm());
        }
        else // an XOF
        {
            this.mgfDigest = DigestFactory.getDigest(paramSpec.getMGFAlgorithm());
        }
        this.saltLength = paramSpec.getSaltLength();
        this.trailer = getTrailer(paramSpec.getTrailerField());
        this.isRaw = isRaw;

        setupContentDigest();
    }
    
    protected void engineInitVerify(
        PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof RSAPublicKey))
        {
            throw new InvalidKeyException("Supplied key is not a RSAPublicKey instance");
        }

        key = RSAUtil.generatePublicKeyParameter((RSAPublicKey)publicKey);
        pss = new com.github.zhenwei.core.crypto.signers.PSSSigner(signer, contentDigest, mgfDigest, saltLength, trailer);
        pss.init(false, key);
        isInitState = true;
    }

    protected void engineInitSign(
        PrivateKey privateKey,
        SecureRandom random)
        throws InvalidKeyException
    {
        this.random = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        if (!(privateKey instanceof RSAPrivateKey))
        {
            throw new InvalidKeyException("Supplied key is not a RSAPrivateKey instance");
        }

        key = RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)privateKey);
        pss = new com.github.zhenwei.core.crypto.signers.PSSSigner(signer, contentDigest, mgfDigest, saltLength, trailer);

        if (random != null)
        {
            pss.init(true, new ParametersWithRandom(key, random));
        }
        else
        {
            pss.init(true, key);
        }

        isInitState = true;
    }

    protected void engineUpdate(
        byte    b)
        throws SignatureException
    {
        pss.update(b);
        isInitState = false;
    }

    protected void engineUpdate(
        byte[]  b,
        int     off,
        int     len) 
        throws SignatureException
    {
        pss.update(b, off, len);
        isInitState = false;
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        isInitState = true;
        try
        {
            return pss.generateSignature();
        }
        catch (CryptoException e)
        {
            throw new SignatureException(e.getMessage());
        }
    }

    protected boolean engineVerify(
        byte[]  sigBytes) 
        throws SignatureException
    {
        isInitState = true;
        return pss.verifySignature(sigBytes);
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            if (originalSpec != null)
            {
                params = originalSpec;
            }
            else
            {
                return;  // Java 11 bug
            }
        }

        if (!isInitState)
        {
            throw new ProviderException("cannot call setParameter in the middle of update");
        }

        if (params instanceof PSSParameterSpec)
        {
            PSSParameterSpec newParamSpec = (PSSParameterSpec)params;
            
            if (originalSpec != null)
            {
                if (!DigestFactory.isSameDigest(originalSpec.getDigestAlgorithm(), newParamSpec.getDigestAlgorithm()))
                {
                    throw new InvalidAlgorithmParameterException("parameter must be using " + originalSpec.getDigestAlgorithm());
                }
            }

            Digest mgfDigest;
            if (newParamSpec.getMGFAlgorithm().equalsIgnoreCase("MGF1")
                || newParamSpec.getMGFAlgorithm().equals(PKCSObjectIdentifiers.id_mgf1.getId()))
            {
                if (!(newParamSpec.getMGFParameters() instanceof MGF1ParameterSpec))
                {
                    throw new InvalidAlgorithmParameterException("unknown MGF parameters");
                }

                MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)newParamSpec.getMGFParameters();

                if (!DigestFactory.isSameDigest(mgfParams.getDigestAlgorithm(), newParamSpec.getDigestAlgorithm()))
                {
                    throw new InvalidAlgorithmParameterException("digest algorithm for MGF should be the same as for PSS parameters.");
                }

                mgfDigest = DigestFactory.getDigest(mgfParams.getDigestAlgorithm());
            }
            else if (newParamSpec.getMGFAlgorithm().equals("SHAKE128")
                    || newParamSpec.getMGFAlgorithm().equals("SHAKE256"))
            {
                mgfDigest = DigestFactory.getDigest(newParamSpec.getMGFAlgorithm());
            }
            else
            {
                throw new InvalidAlgorithmParameterException("unknown mask generation function specified");
            }

            if (mgfDigest == null)
            {
                throw new InvalidAlgorithmParameterException("no match on MGF algorithm: "+ newParamSpec.getMGFAlgorithm());
            }

            this.engineParams = null;
            this.paramSpec = newParamSpec;
            this.mgfDigest = mgfDigest;
            this.saltLength = paramSpec.getSaltLength();
            this.trailer = getTrailer(paramSpec.getTrailerField());

            setupContentDigest();

            if (key != null)
            {
                pss = new com.github.zhenwei.core.crypto.signers.PSSSigner(signer, contentDigest, mgfDigest, saltLength, trailer);
                if (key.isPrivate())
                {
                    pss.init(true, key);
                }
                else
                {
                    pss.init(false, key);
                }
            }
        }
        else
        {
            throw new InvalidAlgorithmParameterException("Only PSSParameterSpec supported");
        }
    }

    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            if (paramSpec != null)
            {
                if (paramSpec.getDigestAlgorithm().equals(paramSpec.getMGFAlgorithm())
                    && paramSpec.getMGFParameters() == null)
                {
                    return null; // must be RFC 8702 SHAKE128 or SHAKE256
                }
                try
                {
                    engineParams = helper.createAlgorithmParameters("PSS");
                    engineParams.init(paramSpec);
                }
                catch (Exception e)
                {
                    throw new RuntimeException(e.toString());
                }
            }
        }

        return engineParams;
    }
    
    /**
     * @deprecated replaced with <a href="#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">engineSetParameter(java.security.spec.AlgorithmParameterSpec)</a>
     */
    protected void engineSetParameter(
        String param,
        Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }
    
    protected Object engineGetParameter(
        String param)
    {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    static public class nonePSS
        extends PSSSignatureSpi
    {
        public nonePSS()
        {
            super(new RSABlindedEngine(), null, true);
        }
    }

    static public class PSSwithRSA
        extends PSSSignatureSpi
    {
        public PSSwithRSA()
        {
            super(new RSABlindedEngine(), null);
        }
    }
    
    static public class SHA1withRSA
        extends PSSSignatureSpi
    {
        public SHA1withRSA()
        {
            super(new RSABlindedEngine(), PSSParameterSpec.DEFAULT);
        }
    }

    static public class SHA1withRSAandSHAKE128
        extends PSSSignatureSpi
    {
        public SHA1withRSAandSHAKE128()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA1", "SHAKE128", null, 20, 1));
        }
    }

    static public class SHA1withRSAandSHAKE256
        extends PSSSignatureSpi
    {
        public SHA1withRSAandSHAKE256()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA1", "SHAKE256", null, 20, 1));
        }
    }

    static public class SHA224withRSA
        extends PSSSignatureSpi
    {
        public SHA224withRSA()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), 28, 1));
        }
    }

    static public class SHA224withRSAandSHAKE128
        extends PSSSignatureSpi
    {
        public SHA224withRSAandSHAKE128()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-224", "SHAKE128", null, 28, 1));
        }
    }

    static public class SHA224withRSAandSHAKE256
        extends PSSSignatureSpi
    {
        public SHA224withRSAandSHAKE256()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-224", "SHAKE256", null, 28, 1));
        }
    }

    static public class SHA256withRSA
        extends PSSSignatureSpi
    {
        public SHA256withRSA()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
        }
    }

    static public class SHA256withRSAandSHAKE128
        extends PSSSignatureSpi
    {
        public SHA256withRSAandSHAKE128()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-256", "SHAKE128", null, 32, 1));
        }
    }

    static public class SHA256withRSAandSHAKE256
        extends PSSSignatureSpi
    {
        public SHA256withRSAandSHAKE256()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-256", "SHAKE256", null, 32, 1));
        }
    }

    static public class SHA384withRSA
        extends PSSSignatureSpi
    {
        public SHA384withRSA()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 48, 1));
        }
    }

    static public class SHA384withRSAandSHAKE128
        extends PSSSignatureSpi
    {
        public SHA384withRSAandSHAKE128()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-384", "SHAKE128", null, 48, 1));
        }
    }

    static public class SHA384withRSAandSHAKE256
        extends PSSSignatureSpi
    {
        public SHA384withRSAandSHAKE256()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-384", "SHAKE256", null, 48, 1));
        }
    }

    static public class SHA512withRSA
        extends PSSSignatureSpi
    {
        public SHA512withRSA()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"), 64, 1));
        }
    }

    static public class SHA512withRSAandSHAKE128
        extends PSSSignatureSpi
    {
        public SHA512withRSAandSHAKE128()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512", "SHAKE128", null, 64, 1));
        }
    }

    static public class SHA512withRSAandSHAKE256
        extends PSSSignatureSpi
    {
        public SHA512withRSAandSHAKE256()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512", "SHAKE256", null, 64, 1));
        }
    }

    static public class SHA512_224withRSA
        extends PSSSignatureSpi
    {
        public SHA512_224withRSA()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(224)", "MGF1", new MGF1ParameterSpec("SHA-512(224)"), 28, 1));
        }
    }

    static public class SHA512_224withRSAandSHAKE128
        extends PSSSignatureSpi
    {
        public SHA512_224withRSAandSHAKE128()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(224)", "SHAKE128", null, 28, 1));
        }
    }

    static public class SHA512_224withRSAandSHAKE256
        extends PSSSignatureSpi
    {
        public SHA512_224withRSAandSHAKE256()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(224)", "SHAKE256", null, 28, 1));
        }
    }

    static public class SHA512_256withRSA
        extends PSSSignatureSpi
    {
        public SHA512_256withRSA()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(256)", "MGF1", new MGF1ParameterSpec("SHA-512(256)"), 32, 1));
        }
    }

    static public class SHA512_256withRSAandSHAKE128
        extends PSSSignatureSpi
    {
        public SHA512_256withRSAandSHAKE128()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(256)", "SHAKE128", null, 32, 1));
        }
    }

    static public class SHA512_256withRSAandSHAKE256
        extends PSSSignatureSpi
    {
        public SHA512_256withRSAandSHAKE256()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(256)", "SHAKE256", null, 32, 1));
        }
    }

    static public class SHA3_224withRSA
        extends PSSSignatureSpi
    {
        public SHA3_224withRSA()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-224", "MGF1", new MGF1ParameterSpec("SHA3-224"), 28, 1));
        }
    }

    static public class SHA3_224withRSAandSHAKE128
        extends PSSSignatureSpi
    {
        public SHA3_224withRSAandSHAKE128()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-224", "SHAKE128", null, 28, 1));
        }
    }

    static public class SHA3_224withRSAandSHAKE256
        extends PSSSignatureSpi
    {
        public SHA3_224withRSAandSHAKE256()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-224", "SHAKE256", null, 28, 1));
        }
    }

    static public class SHA3_256withRSA
        extends PSSSignatureSpi
    {
        public SHA3_256withRSA()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-256", "MGF1", new MGF1ParameterSpec("SHA3-256"), 32, 1));
        }
    }

    static public class SHA3_256withRSAandSHAKE128
        extends PSSSignatureSpi
    {
        public SHA3_256withRSAandSHAKE128()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-256", "SHAKE128", null, 32, 1));
        }
    }

    static public class SHA3_256withRSAandSHAKE256
        extends PSSSignatureSpi
    {
        public SHA3_256withRSAandSHAKE256()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-256", "SHAKE256", null, 32, 1));
        }
    }

    static public class SHA3_384withRSA
        extends PSSSignatureSpi
    {
        public SHA3_384withRSA()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-384", "MGF1", new MGF1ParameterSpec("SHA3-384"), 48, 1));
        }
    }

    static public class SHA3_384withRSAandSHAKE128
        extends PSSSignatureSpi
    {
        public SHA3_384withRSAandSHAKE128()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-384", "SHAKE128", null, 48, 1));
        }
    }

    static public class SHA3_384withRSAandSHAKE256
        extends PSSSignatureSpi
    {
        public SHA3_384withRSAandSHAKE256()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-384", "SHAKE256", null, 48, 1));
        }
    }

    static public class SHA3_512withRSA
        extends PSSSignatureSpi
    {
        public SHA3_512withRSA()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-512", "MGF1", new MGF1ParameterSpec("SHA3-512"), 64, 1));
        }
    }

    static public class SHA3_512withRSAandSHAKE128
        extends PSSSignatureSpi
    {
        public SHA3_512withRSAandSHAKE128()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-512", "SHAKE128", null, 64, 1));
        }
    }

    static public class SHA3_512withRSAandSHAKE256
        extends PSSSignatureSpi
    {
        public SHA3_512withRSAandSHAKE256()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-512", "SHAKE256", null, 64, 1));
        }
    }

    static public class SHAKE128WithRSAPSS
        extends PSSSignatureSpi
    {
        public SHAKE128WithRSAPSS()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHAKE128", "SHAKE128", null, 32, 1));
        }
    }

    static public class SHAKE256WithRSAPSS
        extends PSSSignatureSpi
    {
        public SHAKE256WithRSAPSS()
        {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHAKE256", "SHAKE256", null, 64, 1));
        }
    }

    private class NullPssDigest
        implements Digest
    {
        private ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        private Digest baseDigest;
        private boolean oddTime = true;

        public NullPssDigest(Digest mgfDigest)
        {
            this.baseDigest = mgfDigest;
        }

        public String getAlgorithmName()
        {
            return "NULL";
        }

        public int getDigestSize()
        {
            return baseDigest.getDigestSize();
        }

        public void update(byte in)
        {
            bOut.write(in);
        }

        public void update(byte[] in, int inOff, int len)
        {
            bOut.write(in, inOff, len);
        }

        public int doFinal(byte[] out, int outOff)
        {
            byte[] res = bOut.toByteArray();

            if (oddTime)
            {
                System.arraycopy(res, 0, out, outOff, res.length);
            }
            else
            {
                baseDigest.update(res, 0, res.length);

                baseDigest.doFinal(out, outOff);
            }

            reset();

            oddTime = !oddTime;

            return res.length;
        }

        public void reset()
        {
            bOut.reset();
            baseDigest.reset();
        }

        public int getByteLength()
        {
            return 0;
        }
    }
}