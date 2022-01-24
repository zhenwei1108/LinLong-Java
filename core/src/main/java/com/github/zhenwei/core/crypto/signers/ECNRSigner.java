package com.github.zhenwei.core.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPair;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.CryptoServicesRegistrar;
import com.github.zhenwei.core.crypto.DSAExt;
import com.github.zhenwei.core.crypto.DataLengthException;
import com.github.zhenwei.core.crypto.generators.ECKeyPairGenerator;
import com.github.zhenwei.core.crypto.params.ECKeyGenerationParameters;
import com.github.zhenwei.core.crypto.params.ECKeyParameters;
import com.github.zhenwei.core.crypto.params.ECPrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.ECPublicKeyParameters;
import com.github.zhenwei.core.crypto.params.ParametersWithRandom;
import com.github.zhenwei.core.math.ec.ECAlgorithms;
import com.github.zhenwei.core.math.ec.ECConstants;
import com.github.zhenwei.core.math.ec.ECPoint;
import com.github.zhenwei.core.util.BigIntegers;

/**
 * EC-NR as described in IEEE 1363-2000 - a signature algorithm for Elliptic Curve which
 * also offers message recovery.
 */
public class ECNRSigner
    implements DSAExt
{
    private boolean             forSigning;
    private ECKeyParameters     key;
    private SecureRandom        random;

    /**
     * Initialise the signer.
     *
     * @param forSigning true if we are generating a signature, false
     * for verification or if we want to use the signer for message recovery.
     * @param param key parameters for signature generation.
     */
    public void init(
        boolean          forSigning, 
        CipherParameters param) 
    {
        this.forSigning = forSigning;
        
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom    rParam = (ParametersWithRandom)param;

                this.random = rParam.getRandom();
                this.key = (ECPrivateKeyParameters)rParam.getParameters();
            }
            else
            {
                this.random = CryptoServicesRegistrar.getSecureRandom();
                this.key = (ECPrivateKeyParameters)param;
            }
        }
        else
        {
            this.key = (ECPublicKeyParameters)param;
        }
    }

    public BigInteger getOrder()
    {
        return key.getParameters().getN();
    }

    // Section 7.2.5 ECSP-NR, pg 34
    /**
     * generate a signature for the given message using the key we were
     * initialised with.  Generally, the order of the curve should be at 
     * least as long as the hash of the message of interest, and with 
     * ECNR it *must* be at least as long.  
     *
     * @param digest  the digest to be signed.
     * @exception DataLengthException if the digest is longer than the key allows
     */
    public BigInteger[] generateSignature(
        byte[] digest)
    {
        if (!this.forSigning) 
        {
            throw new IllegalStateException("not initialised for signing");
        }
        
        BigInteger n = getOrder();
        
        BigInteger e = new BigInteger(1, digest);

        ECPrivateKeyParameters  privKey = (ECPrivateKeyParameters)key;

        if (e.compareTo(n) >= 0)
        {
            throw new DataLengthException("input too large for ECNR key");
        }

        BigInteger r = null;
        BigInteger s = null;

        AsymmetricCipherKeyPair tempPair;
        do // generate r
        {
            // generate another, but very temporary, key pair using 
            // the same EC parameters
            ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
            
            keyGen.init(new ECKeyGenerationParameters(privKey.getParameters(), this.random));
            
            tempPair = keyGen.generateKeyPair();

            //    BigInteger Vx = tempPair.getPublic().getW().getAffineX();
            ECPublicKeyParameters V = (ECPublicKeyParameters)tempPair.getPublic();        // get temp's public key
            BigInteger Vx = V.getQ().getAffineXCoord().toBigInteger();                    // get the point's x coordinate

            r = Vx.add(e).mod(n);
        }
        while (r.equals(ECConstants.ZERO));

        // generate s
        BigInteger x = privKey.getD();                // private key value
        BigInteger u = ((ECPrivateKeyParameters)tempPair.getPrivate()).getD();    // temp's private key value
        s = u.subtract(r.multiply(x)).mod(n);

        BigInteger[]  res = new BigInteger[2];
        res[0] = r;
        res[1] = s;

        return res;
    }

    // Section 7.2.6 ECVP-NR, pg 35
    /**
     * return true if the value r and s represent a signature for the 
     * message passed in. Generally, the order of the curve should be at 
     * least as long as the hash of the message of interest, and with 
     * ECNR, it *must* be at least as long.  But just in case the signer
     * applied mod(n) to the longer digest, this implementation will
     * apply mod(n) during verification.
     *
     * @param digest  the digest to be verified.
     * @param r       the r value of the signature.
     * @param s       the s value of the signature.
     * @exception DataLengthException if the digest is longer than the key allows
     */
    public boolean verifySignature(
        byte[]      digest,
        BigInteger  r,
        BigInteger  s)
    {
        if (this.forSigning) 
        {
            throw new IllegalStateException("not initialised for verifying");
        }

        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)key;
        BigInteger n = pubKey.getParameters().getN();
        int nBitLength = n.bitLength();
        
        BigInteger e = new BigInteger(1, digest);
        int eBitLength = e.bitLength();
        
        if (eBitLength > nBitLength) 
        {
            throw new DataLengthException("input too large for ECNR key.");
        }

        BigInteger t = extractT(pubKey, r, s);

        return t != null && t.equals(e.mod(n));
    }

    /**
     * Returns the data used for the signature generation, assuming the public key passed
     * to init() is correct.
     *
     * @return null if r and s are not valid.
     */
    public byte[] getRecoveredMessage(BigInteger r, BigInteger s)
    {
        if (this.forSigning)
        {
            throw new IllegalStateException("not initialised for verifying/recovery");
        }

        BigInteger t = extractT((ECPublicKeyParameters)key, r, s);

        if (t != null)
        {
            return BigIntegers.asUnsignedByteArray(t);
        }

        return null;
    }

    private BigInteger extractT(ECPublicKeyParameters pubKey, BigInteger r, BigInteger s)
    {
        BigInteger n = pubKey.getParameters().getN();

        // r in the range [1,n-1]
        if (r.compareTo(ECConstants.ONE) < 0 || r.compareTo(n) >= 0)
        {
            return null;
        }

        // s in the range [0,n-1]           NB: ECNR spec says 0
        if (s.compareTo(ECConstants.ZERO) < 0 || s.compareTo(n) >= 0)
        {
            return null;
        }

        // compute P = sG + rW

        ECPoint G = pubKey.getParameters().getG();
        ECPoint W = pubKey.getQ();
        // calculate P using Bouncy math
        ECPoint P = ECAlgorithms.sumOfTwoMultiplies(G, s, W, r).normalize();

        // components must be bogus.
        if (P.isInfinity())
        {
            return null;
        }

        BigInteger x = P.getAffineXCoord().toBigInteger();

        return r.subtract(x).mod(n);
    }
}