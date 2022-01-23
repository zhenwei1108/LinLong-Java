package com.github.zhenwei.pkix.operator.bc;


import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
 
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
 
 
 


public class BcRSAAsymmetricKeyUnwrapper
    extends BcAsymmetricKeyUnwrapper
{
    public BcRSAAsymmetricKeyUnwrapper(
        AlgorithmIdentifier encAlgId, AsymmetricKeyParameter privateKey)
    {
        super(encAlgId, privateKey);
    }

    protected AsymmetricBlockCipher createAsymmetricUnwrapper(ASN1ObjectIdentifier algorithm)
    {
        return new PKCS1Encoding(new RSABlindedEngine());
    }
}