package com.github.zhenwei.core.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;

public class ECPrivateKeyParameters
    extends ECKeyParameters
{
    private final BigInteger d;

    public ECPrivateKeyParameters(
        BigInteger          d,
        ECDomainParameters  parameters)
    {
        super(true, parameters);

        this.d = parameters.validatePrivateScalar(d);
    }

    public BigInteger getD()
    {
        return d;
    }
}