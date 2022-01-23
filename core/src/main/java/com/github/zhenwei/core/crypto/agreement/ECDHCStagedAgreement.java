package com.github.zhenwei.core.crypto.agreement;


import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.ECDomainParameters;
import com.github.zhenwei.core.crypto.params.ECPrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.ECPublicKeyParameters;
import com.github.zhenwei.core.math.ec.ECAlgorithms;
import com.github.zhenwei.core.math.ec.ECPoint;
import java.math.BigInteger;
import org.bouncycastle.crypto.StagedAgreement;

public class ECDHCStagedAgreement
    implements StagedAgreement
{
    ECPrivateKeyParameters key;

    public void init(
        CipherParameters key)
    {
        this.key = (ECPrivateKeyParameters)key;
    }

    public int getFieldSize()
    {
        return (key.getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    public AsymmetricKeyParameter calculateStage(
        CipherParameters pubKey)
    {
        ECPoint P = calculateNextPoint((ECPublicKeyParameters)pubKey);

        return new ECPublicKeyParameters(P, key.getParameters());
    }

    public BigInteger calculateAgreement(
        CipherParameters pubKey)
    {
        ECPoint P = calculateNextPoint((ECPublicKeyParameters)pubKey);

        return P.getAffineXCoord().toBigInteger();
    }

    private ECPoint calculateNextPoint(ECPublicKeyParameters pubKey)
    {
        ECPublicKeyParameters pub = pubKey;
        ECDomainParameters params = key.getParameters();
        if (!params.equals(pub.getParameters()))
        {
            throw new IllegalStateException("ECDHC public key has wrong domain parameters");
        }

        BigInteger hd = params.getH().multiply(key.getD()).mod(params.getN());

        // Always perform calculations on the exact curve specified by our private key's parameters
        ECPoint pubPoint = ECAlgorithms.cleanPoint(params.getCurve(), pub.getQ());
        if (pubPoint.isInfinity())
        {
            throw new IllegalStateException("Infinity is not a valid public key for ECDHC");
        }

        ECPoint P = pubPoint.multiply(hd).normalize();

        if (P.isInfinity())
        {
            throw new IllegalStateException("Infinity is not a valid agreement value for ECDHC");
        }

        return P;
    }
}