package com.github.zhenwei.pkix.operator;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.io.SignerOutputStream;
import com.github.zhenwei.core.crypto.signers.HsmSigner;
import com.github.zhenwei.core.enums.SignAlgEnum;

import java.io.OutputStream;
import java.security.Provider;
import java.security.Signature;

public class HsmContentSignerBuilder implements ContentSigner {

    private SignAlgEnum sigAlg;

    private SignerOutputStream signerOutputStream;
    Signature signature;

    public HsmContentSignerBuilder(SignAlgEnum signAlg, Provider provider) throws Exception {
        this.sigAlg = signAlg;
        signature = Signature.getInstance(signAlg.getAlg(), provider);
        signerOutputStream = new SignerOutputStream(new HsmSigner(signature));
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return new AlgorithmIdentifier(sigAlg.getOid());
    }

    @Override
    public OutputStream getOutputStream() {
        return signerOutputStream;
    }

    @Override
    public byte[] getSignature() {
        try {
            return signerOutputStream.getSigner().generateSignature();
        } catch (Exception e) {
            throw new RuntimeException("HsmContentSignerBuilder get sinature error", e);
        }
    }
}
