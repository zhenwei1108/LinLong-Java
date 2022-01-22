package com.github.zhenwei.pkix.operator.bc;


import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
 
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;


public class BcECContentSignerBuilder
    extends BcContentSignerBuilder
{
    public BcECContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
    {
        super(sigAlgId, digAlgId);
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
    {
        Digest dig = digestProvider.get(digAlgId);

        return new DSADigestSigner(new ECDSASigner(), dig);
    }
}