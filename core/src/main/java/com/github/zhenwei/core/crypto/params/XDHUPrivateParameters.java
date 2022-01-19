package com.github.zhenwei.core.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;

/**
 * Parameters holder for private unified static/ephemeral agreement using Edwards Curves.
 */
public class XDHUPrivateParameters
    implements CipherParameters
{
    private AsymmetricKeyParameter staticPrivateKey;
    private AsymmetricKeyParameter ephemeralPrivateKey;
    private AsymmetricKeyParameter ephemeralPublicKey;

    public XDHUPrivateParameters(
        AsymmetricKeyParameter  staticPrivateKey,
        AsymmetricKeyParameter  ephemeralPrivateKey)
    {
        this(staticPrivateKey, ephemeralPrivateKey, null);
    }

    public XDHUPrivateParameters(
        AsymmetricKeyParameter  staticPrivateKey,
        AsymmetricKeyParameter  ephemeralPrivateKey,
        AsymmetricKeyParameter  ephemeralPublicKey)
    {
        if (staticPrivateKey == null)
        {
            throw new NullPointerException("staticPrivateKey cannot be null");
        }
        if (!(staticPrivateKey instanceof X448PrivateKeyParameters || staticPrivateKey instanceof X25519PrivateKeyParameters))
        {
            throw new IllegalArgumentException("only X25519 and X448 paramaters can be used");
        }
        if (ephemeralPrivateKey == null)
        {
            throw new NullPointerException("ephemeralPrivateKey cannot be null");
        }

        if (!staticPrivateKey.getClass().isAssignableFrom(ephemeralPrivateKey.getClass()))
        {
            throw new IllegalArgumentException("static and ephemeral private keys have different domain parameters");
        }

        if (ephemeralPublicKey == null)
        {
            if (ephemeralPrivateKey instanceof X448PrivateKeyParameters)
            {
                ephemeralPublicKey = ((X448PrivateKeyParameters)ephemeralPrivateKey).generatePublicKey();
            }
            else
            {
                ephemeralPublicKey = ((X25519PrivateKeyParameters)ephemeralPrivateKey).generatePublicKey();
            }
        }
        else
        {
            if (ephemeralPublicKey instanceof X448PublicKeyParameters && !(staticPrivateKey instanceof X448PrivateKeyParameters))
            {
                throw new IllegalArgumentException("ephemeral public key has different domain parameters");
            }
            if (ephemeralPublicKey instanceof X25519PublicKeyParameters && !(staticPrivateKey instanceof X25519PrivateKeyParameters))
            {
                throw new IllegalArgumentException("ephemeral public key has different domain parameters");
            }
        }

        this.staticPrivateKey = staticPrivateKey;
        this.ephemeralPrivateKey = ephemeralPrivateKey;
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public AsymmetricKeyParameter getStaticPrivateKey()
    {
        return staticPrivateKey;
    }

    public AsymmetricKeyParameter getEphemeralPrivateKey()
    {
        return ephemeralPrivateKey;
    }

    public AsymmetricKeyParameter getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }
}