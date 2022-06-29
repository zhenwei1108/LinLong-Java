package com.github.zhenwei.core.crypto.params;

import com.github.zhenwei.core.crypto.CipherParameters;

import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyParameters implements CipherParameters {

    private PrivateKey privateKey;

    private PublicKey publicKey;

    public KeyParameters(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public KeyParameters(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
