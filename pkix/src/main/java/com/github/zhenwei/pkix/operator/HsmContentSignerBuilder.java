package com.github.zhenwei.pkix.operator;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.operator.bc.BcDigestProvider;

import java.io.OutputStream;
import java.security.SecureRandom;

public class HsmContentSignerBuilder implements ContentSigner {

    private SecureRandom random;
    private AlgorithmIdentifier sigAlgId;
    private AlgorithmIdentifier digAlgId;

    protected BcDigestProvider digestProvider;


    public HsmContentSignerBuilder(SecureRandom random, AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId) {
        this.random = random;
        this.sigAlgId = sigAlgId;
        this.digAlgId = digAlgId;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return null;
    }

    @Override
    public OutputStream getOutputStream() {
        return null;
    }

    @Override
    public byte[] getSignature() {
        return new byte[0];
    }
}
