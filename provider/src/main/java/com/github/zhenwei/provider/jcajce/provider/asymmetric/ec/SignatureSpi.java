package com.github.zhenwei.provider.jcajce.provider.asymmetric.ec;

import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.util.DigestFactory;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.crypto.DSAExt;
import  NullDigest;
import  RIPEMD160Digest;
import  SHAKEDigest;
 
import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.ECNRSigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jcajce.provider.asymmetric.util.DSABase;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

public class SignatureSpi
    extends DSABase
{
    SignatureSpi(Digest digest, DSAExt signer, DSAEncoding encoding)
    {
        super(digest, signer, encoding);
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        CipherParameters param = ECUtils.generatePublicKeyParameter(publicKey);

        digest.reset();
        signer.init(false, param);
    }

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        CipherParameters param = ECUtil.generatePrivateKeyParameter(privateKey);

        digest.reset();

        if (appRandom != null)
        {
            signer.init(true, new ParametersWithRandom(param, appRandom));
        }
        else
        {
            signer.init(true, param);
        }
    }

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }
    
    static public class ecDSA
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDSA()
        {
            super(DigestFactory.createSHA1(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSA
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDetDSA()
        {
            super(DigestFactory.createSHA1(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA1())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSAnone
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDSAnone()
        {
            super(new NullDigest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSA224
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDSA224()
        {
            super(DigestFactory.createSHA224(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSA224
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDetDSA224()
        {
            super(DigestFactory.createSHA224(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA224())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSA256
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDSA256()
        {
            super(DigestFactory.createSHA256(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSA256
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDetDSA256()
        {
            super(DigestFactory.createSHA256(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA256())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSA384
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDSA384()
        {
            super(DigestFactory.createSHA384(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSA384
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDetDSA384()
        {
            super(DigestFactory.createSHA384(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA384())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSA512
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDSA512()
        {
            super(DigestFactory.createSHA512(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSA512
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDetDSA512()
        {
            super(DigestFactory.createSHA512(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA512())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSASha3_224
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDSASha3_224()
        {
            super(DigestFactory.createSHA3_224(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSASha3_224
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDetDSASha3_224()
        {
            super(DigestFactory.createSHA3_224(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_224())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSASha3_256
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDSASha3_256()
        {
            super(DigestFactory.createSHA3_256(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSASha3_256
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDetDSASha3_256()
        {
            super(DigestFactory.createSHA3_256(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_256())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSASha3_384
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDSASha3_384()
        {
            super(DigestFactory.createSHA3_384(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSASha3_384
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDetDSASha3_384()
        {
            super(DigestFactory.createSHA3_384(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_384())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSASha3_512
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDSASha3_512()
        {
            super(DigestFactory.createSHA3_512(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSASha3_512
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDetDSASha3_512()
        {
            super(DigestFactory.createSHA3_512(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_512())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSARipeMD160
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDSARipeMD160()
        {
            super(new RIPEMD160Digest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSAShake128
         extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDSAShake128()
        {
            // RFC 8702 specifies deterministic DSA
            super(new SHAKEDigest(128), new ECDSASigner(new HMacDSAKCalculator(new SHAKEDigest(128))), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSAShake256
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecDSAShake256()
        {
            // RFC 8702 specifies deterministic DSA
            super(new SHAKEDigest(256), new ECDSASigner(new HMacDSAKCalculator(new SHAKEDigest(256))), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecNR()
        {
            super(DigestFactory.createSHA1(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR224
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecNR224()
        {
            super(DigestFactory.createSHA224(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR256
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecNR256()
        {
            super(DigestFactory.createSHA256(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR384
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecNR384()
        {
            super(DigestFactory.createSHA384(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR512
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecNR512()
        {
            super(DigestFactory.createSHA512(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecCVCDSA()
        {
            super(DigestFactory.createSHA1(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA224
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecCVCDSA224()
        {
            super(DigestFactory.createSHA224(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA256
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecCVCDSA256()
        {
            super(DigestFactory.createSHA256(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA384
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecCVCDSA384()
        {
            super(DigestFactory.createSHA384(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA512
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecCVCDSA512()
        {
            super(DigestFactory.createSHA512(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecPlainDSARP160
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecPlainDSARP160()
        {
            super(new RIPEMD160Digest(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA3_224
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecCVCDSA3_224()
        {
            super(DigestFactory.createSHA3_224(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA3_256
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecCVCDSA3_256()
        {
            super(DigestFactory.createSHA3_256(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA3_384
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecCVCDSA3_384()
        {
            super(DigestFactory.createSHA3_384(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA3_512
        extends org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi
    {
        public ecCVCDSA3_512()
        {
            super(DigestFactory.createSHA3_512(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }
}