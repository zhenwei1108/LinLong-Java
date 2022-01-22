package com.github.zhenwei.pkix.cms.jcajce;



interface KeyMaterialGenerator
{
    byte[] generateKDFMaterial(AlgorithmIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters);
}