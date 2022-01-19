package com.github.zhenwei.core.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Public key parameters for NaccacheStern cipher. For details on this cipher,
 * please see
 * 
 * https://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
 */
public class NaccacheSternKeyParameters extends AsymmetricKeyParameter
{

    private BigInteger g, n;

    int lowerSigmaBound;

    /**
     * @param privateKey
     */
    public NaccacheSternKeyParameters(boolean privateKey, BigInteger g, BigInteger n, int lowerSigmaBound)
    {
        super(privateKey);
        this.g = g;
        this.n = n;
        this.lowerSigmaBound = lowerSigmaBound;
    }

    /**
     * @return Returns the g.
     */
    public BigInteger getG()
    {
        return g;
    }

    /**
     * @return Returns the lowerSigmaBound.
     */
    public int getLowerSigmaBound()
    {
        return lowerSigmaBound;
    }

    /**
     * @return Returns the n.
     */
    public BigInteger getModulus()
    {
        return n;
    }

}