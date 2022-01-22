package com.github.zhenwei.provider.jcajce.provider.asymmetric.ecgost12;


import com.github.zhenwei.core.asn1.cryptopro.ECGOST3410NamedCurves;
import com.github.zhenwei.core.asn1.x9.X9ECParameters;
import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPair;
import com.github.zhenwei.core.crypto.params.ECDomainParameters;
import com.github.zhenwei.core.crypto.params.ECGOST3410Parameters;
import com.github.zhenwei.core.crypto.params.ECNamedDomainParameters;
import com.github.zhenwei.core.crypto.params.ECPrivateKeyParameters;
import com.github.zhenwei.core.math.ec.ECCurve;
import com.github.zhenwei.provider.jce.provider.BouncyCastleProvider;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import ECKeyPairGenerator;
import ECKeyGenerationParameters;
import ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;

;


/**
 * KeyPairGenerator for GOST34.10 2012. Algorithm is the same as for GOST34.10 2001
 */
public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    Object ecParams = null;
    ECKeyPairGenerator engine = new ECKeyPairGenerator();

    String algorithm = "ECGOST3410-2012";
    ECKeyGenerationParameters param;
    int strength = 239;
    SecureRandom random = null;
    boolean initialised = false;

    public KeyPairGeneratorSpi()
    {
        super("ECGOST3410-2012");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        this.strength = strength;
        this.random = random;

        if (ecParams != null)
        {
            try
            {
                initialize((ECGenParameterSpec)ecParams, random);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                throw new InvalidParameterException("key size not configurable.");
            }
        }
        else
        {
            throw new InvalidParameterException("unknown key size.");
        }
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (params instanceof GOST3410ParameterSpec)
        {
            GOST3410ParameterSpec gostParams = (GOST3410ParameterSpec)params;

            init(gostParams, random);
        }
        else if (params instanceof ECParameterSpec)
        {
            ECParameterSpec p = (ECParameterSpec)params;
            this.ecParams = params;

            param = new ECKeyGenerationParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH()), random);

            engine.init(param);
            initialised = true;
        }
        else if (params instanceof java.security.spec.ECParameterSpec)
        {
            java.security.spec.ECParameterSpec p = (java.security.spec.ECParameterSpec)params;
            this.ecParams = params;

            ECCurve curve = EC5Util.convertCurve(p.getCurve());
            ECPoint g = EC5Util.convertPoint(curve, p.getGenerator());

            param = new ECKeyGenerationParameters(new ECDomainParameters(curve, g, p.getOrder(), BigInteger.valueOf(p.getCofactor())), random);

            engine.init(param);
            initialised = true;
        }
        else if (params instanceof ECGenParameterSpec || params instanceof ECNamedCurveGenParameterSpec)
        {
            String curveName;

            if (params instanceof ECGenParameterSpec)
            {
                curveName = ((ECGenParameterSpec)params).getName();
            }
            else
            {
                curveName = ((ECNamedCurveGenParameterSpec)params).getName();
            }

            init(new GOST3410ParameterSpec(curveName), random);
        }
        else if (params == null && BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa() != null)
        {
            ECParameterSpec p = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
            this.ecParams = params;

            param = new ECKeyGenerationParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH()), random);

            engine.init(param);
            initialised = true;
        }
        else if (params == null && BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa() == null)
        {
            throw new InvalidAlgorithmParameterException("null parameter passed but no implicitCA set");
        }
        else
        {
            throw new InvalidAlgorithmParameterException("parameter object not a ECParameterSpec: " + params.getClass().getName());
        }
    }

    private void init(GOST3410ParameterSpec gostParams, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        X9ECParameters ecP = ECGOST3410NamedCurves.getByOIDX9(gostParams.getPublicKeyParamSet());
        if (ecP == null)
        {
            throw new InvalidAlgorithmParameterException("unknown curve: " + gostParams.getPublicKeyParamSet());
        }

        this.ecParams = new ECNamedCurveSpec(
            ECGOST3410NamedCurves.getName(gostParams.getPublicKeyParamSet()),
            ecP.getCurve(),
            ecP.getG(),
            ecP.getN(),
            ecP.getH(),
            ecP.getSeed());

        param = new ECKeyGenerationParameters(
            new ECGOST3410Parameters(
                new ECNamedDomainParameters(gostParams.getPublicKeyParamSet(), ecP),
                gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet(), gostParams.getEncryptionParamSet()), random);

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            throw new IllegalStateException("EC Key Pair Generator not initialised");
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        ECPublicKeyParameters pub = (ECPublicKeyParameters)pair.getPublic();
        ECPrivateKeyParameters priv = (ECPrivateKeyParameters)pair.getPrivate();

        if (ecParams instanceof ECParameterSpec)
        {
            ECParameterSpec p = (ECParameterSpec)ecParams;

            BCECGOST3410_2012PublicKey pubKey = new BCECGOST3410_2012PublicKey(algorithm, pub, p);
            return new KeyPair(pubKey,
                new BCECGOST3410_2012PrivateKey(algorithm, priv, pubKey, p));
        }
        else if (ecParams == null)
        {
            return new KeyPair(new BCECGOST3410_2012PublicKey(algorithm, pub),
                new BCECGOST3410_2012PrivateKey(algorithm, priv));
        }
        else
        {
            java.security.spec.ECParameterSpec p = (java.security.spec.ECParameterSpec)ecParams;

            BCECGOST3410_2012PublicKey pubKey = new BCECGOST3410_2012PublicKey(algorithm, pub, p);

            return new KeyPair(pubKey, new BCECGOST3410_2012PrivateKey(algorithm, priv, pubKey, p));
        }
    }
}