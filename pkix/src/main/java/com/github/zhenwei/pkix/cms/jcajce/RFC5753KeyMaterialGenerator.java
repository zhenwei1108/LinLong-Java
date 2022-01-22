package com.github.zhenwei.pkix.cms.jcajce;



import cms.ecc.ECCCMSSharedInfo;
import java.io.IOException;


class RFC5753KeyMaterialGenerator
    implements KeyMaterialGenerator
{
    public byte[] generateKDFMaterial(AlgorithmIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters)
    {
        ECCCMSSharedInfo eccInfo = new ECCCMSSharedInfo(keyAlgorithm, userKeyMaterialParameters, Pack.intToBigEndian(keySize));

        try
        {
            return eccInfo.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("Unable to create KDF material: " + e);
        }
    }
}