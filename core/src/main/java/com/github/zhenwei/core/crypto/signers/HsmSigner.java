package com.github.zhenwei.core.crypto.signers;

import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.CryptoException;
import com.github.zhenwei.core.crypto.DataLengthException;
import com.github.zhenwei.core.crypto.Signer;
import com.github.zhenwei.core.crypto.params.KeyParameters;

import java.security.*;

public class HsmSigner implements Signer {

    private Signature signature;

    public HsmSigner(Signature signature) {
        this.signature = signature;
    }

    public HsmSigner(String alg, Provider provider) throws NoSuchAlgorithmException {
        signature = Signature.getInstance(alg, provider);
    }

    public HsmSigner(String alg, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        signature = Signature.getInstance(alg, provider);
    }

    @Override
    public void init(boolean forSigning, CipherParameters param) {
        if (param instanceof KeyParameters) {
            try {
                KeyParameters keyParameters = (KeyParameters) param;
                if (forSigning) {
                    signature.initSign(keyParameters.getPrivateKey());
                } else {
                    signature.initVerify(keyParameters.getPublicKey());
                }
            } catch (Exception e) {
                throw new RuntimeException("hsm init error ,", e);
            }
        } else throw new RuntimeException("params type error");
    }

    @Override
    public void update(byte b) {
        try {
            signature.update(b);
        } catch (Exception e) {
            throw new RuntimeException("hsm siner update error ", e);
        }
    }

    @Override
    public void update(byte[] in, int off, int len) {
        try {
            signature.update(in, off, len);
        } catch (Exception e) {
            throw new RuntimeException("hsm siner update error ", e);
        }
    }

    @Override
    public byte[] generateSignature() throws CryptoException, DataLengthException {
        try {
            return signature.sign();
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    @Override
    public boolean verifySignature(byte[] data) {
        try {
            return signature.verify(data);
        } catch (SignatureException e) {
            throw new RuntimeException("hsm signer verify error ", e);
        }

    }

    @Override
    public void reset() {
    }
}
