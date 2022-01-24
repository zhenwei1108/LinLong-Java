package com.github.zhenwei.core.crypto.signers;

import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.Signer;
import com.github.zhenwei.core.crypto.params.Ed25519PrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.Ed25519PublicKeyParameters;
import com.github.zhenwei.core.math.ec.rfc8032.Ed25519;
import com.github.zhenwei.core.util.Arrays;

public class Ed25519phSigner
    implements Signer
{
    private final Digest prehash = Ed25519.createPrehash();
    private final byte[] context;

    private boolean forSigning;
    private Ed25519PrivateKeyParameters privateKey;
    private Ed25519PublicKeyParameters publicKey;

    public Ed25519phSigner(byte[] context)
    {
        this.context = Arrays.clone(context);
    }

    public void init(boolean forSigning, CipherParameters parameters)
    {
        this.forSigning = forSigning;

        if (forSigning)
        {
            this.privateKey = (Ed25519PrivateKeyParameters)parameters;
            this.publicKey = null;
        }
        else
        {
            this.privateKey = null;
            this.publicKey = (Ed25519PublicKeyParameters)parameters;
        }

        reset();
    }

    public void update(byte b)
    {
        prehash.update(b);
    }

    public void update(byte[] buf, int off, int len)
    {
        prehash.update(buf, off, len);
    }

    public byte[] generateSignature()
    {
        if (!forSigning || null == privateKey)
        {
            throw new IllegalStateException("Ed25519phSigner not initialised for signature generation.");
        }

        byte[] msg = new byte[Ed25519.PREHASH_SIZE];
        if (Ed25519.PREHASH_SIZE != prehash.doFinal(msg, 0))
        {
            throw new IllegalStateException("Prehash digest failed");
        }

        byte[] signature = new byte[Ed25519PrivateKeyParameters.SIGNATURE_SIZE];
        privateKey.sign(Ed25519.Algorithm.Ed25519ph, context, msg, 0, Ed25519.PREHASH_SIZE, signature, 0);
        return signature;
    }

    public boolean verifySignature(byte[] signature)
    {
        if (forSigning || null == publicKey)
        {
            throw new IllegalStateException("Ed25519phSigner not initialised for verification");
        }
        if (Ed25519.SIGNATURE_SIZE != signature.length)
        {
            prehash.reset();
            return false;
        }

        byte[] pk = publicKey.getEncoded();
        return Ed25519.verifyPrehash(signature, 0, pk, 0, context, prehash);
    }

    public void reset()
    {
        prehash.reset();
    }
}