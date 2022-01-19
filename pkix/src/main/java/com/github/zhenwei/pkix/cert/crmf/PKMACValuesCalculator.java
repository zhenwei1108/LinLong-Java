package com.github.zhenwei.pkix.cert.crmf;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.crmf.CRMFException;

public interface PKMACValuesCalculator
{
    void setup(AlgorithmIdentifier digestAlg, AlgorithmIdentifier macAlg)
        throws CRMFException;

    byte[] calculateDigest(byte[] data)
        throws CRMFException;

    byte[] calculateMac(byte[] pwd, byte[] data)
        throws CRMFException;
}