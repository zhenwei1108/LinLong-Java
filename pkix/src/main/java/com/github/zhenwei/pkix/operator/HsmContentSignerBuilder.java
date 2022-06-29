package com.github.zhenwei.pkix.operator;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.io.SignerOutputStream;
import com.github.zhenwei.core.crypto.signers.HsmSigner;
import com.github.zhenwei.core.enums.SignAlgEnum;
import com.github.zhenwei.pkix.operator.bc.BcDigestProvider;

import java.io.OutputStream;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;

public class HsmContentSignerBuilder implements ContentSigner {

    private SecureRandom random;
    private SignAlgEnum sigAlg;
    private AlgorithmIdentifier digAlgId;

    protected BcDigestProvider digestProvider;

    Signature signature;
    public HsmContentSignerBuilder(SecureRandom random, AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId) {
        this.random = random;
        this.digAlgId = digAlgId;
    }

    public HsmContentSignerBuilder(SignAlgEnum signAlg, Provider provider) throws Exception {
        signature = Signature.getInstance(signAlg.getAlg(), provider);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return new AlgorithmIdentifier(sigAlg.getOid());
    }

    @Override
    public OutputStream getOutputStream() {
        HsmSigner hsmSigner = new HsmSigner(signature);
        SignerOutputStream signerOutputStream = new SignerOutputStream(hsmSigner);
        return null;
    }

    @Override
    public byte[] getSignature() {
        return new byte[0];
    }
}
