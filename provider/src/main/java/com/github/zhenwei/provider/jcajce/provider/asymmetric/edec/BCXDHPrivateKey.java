package com.github.zhenwei.provider.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.edec.EdECObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.X25519PrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.X448PrivateKeyParameters;
import com.github.zhenwei.core.crypto.util.PrivateKeyInfoFactory;
import com.github.zhenwei.provider.jcajce.interfaces.XDHPrivateKey;
import com.github.zhenwei.provider.jcajce.interfaces.XDHPublicKey;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.core.util.Properties;

public class BCXDHPrivateKey
    implements XDHPrivateKey
{
    static final long serialVersionUID = 1L;

    transient AsymmetricKeyParameter xdhPrivateKey;

    private final boolean hasPublicKey;
    private final byte[] attributes;

    BCXDHPrivateKey(AsymmetricKeyParameter privKey)
    {
        this.hasPublicKey = true;
        this.attributes = null;
        this.xdhPrivateKey = privKey;
    }

    BCXDHPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.hasPublicKey = keyInfo.hasPublicKey();
        this.attributes = (keyInfo.getAttributes() != null) ? keyInfo.getAttributes().getEncoded() : null;

        populateFromPrivateKeyInfo(keyInfo);
    }

    private void populateFromPrivateKeyInfo(PrivateKeyInfo keyInfo)
        throws IOException
    {
        byte[] encoding = keyInfo.getPrivateKey().getOctets();

        // exact length of X25519/X448 secret used in Java 11
        if (encoding.length != X25519PrivateKeyParameters.KEY_SIZE &&
            encoding.length != X448PrivateKeyParameters.KEY_SIZE)
        {
            encoding = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
        }

        if (EdECObjectIdentifiers.id_X448.equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()))
        {
            xdhPrivateKey = new X448PrivateKeyParameters(encoding);
        }
        else
        {
            xdhPrivateKey = new X25519PrivateKeyParameters(encoding);
        }
    }

    public String getAlgorithm()
    {
        return (xdhPrivateKey instanceof X448PrivateKeyParameters) ? "X448" : "X25519";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        try
        {
            ASN1Set attrSet = ASN1Set.getInstance(attributes);
            PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(xdhPrivateKey, attrSet);

            if (hasPublicKey && !Properties.isOverrideSet("com.github.zhenwei.pkix.pkcs8.v1_info_only"))
            {
                return privInfo.getEncoded();
            }
            else
            {
                return new PrivateKeyInfo(privInfo.getPrivateKeyAlgorithm(), privInfo.parsePrivateKey(), attrSet).getEncoded();
            }
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public XDHPublicKey getPublicKey()
    {
        if (xdhPrivateKey instanceof X448PrivateKeyParameters)
        {
            return new BCXDHPublicKey(((X448PrivateKeyParameters)xdhPrivateKey).generatePublicKey());
        }
        else
        {
            return new BCXDHPublicKey(((X25519PrivateKeyParameters)xdhPrivateKey).generatePublicKey());
        }
    }

    AsymmetricKeyParameter engineGetKeyParameters()
    {
        return xdhPrivateKey;
    }

    public String toString()
    {
        AsymmetricKeyParameter pubKey;
        if (xdhPrivateKey instanceof X448PrivateKeyParameters)
        {
            pubKey = ((X448PrivateKeyParameters)xdhPrivateKey).generatePublicKey();
        }
        else
        {
            pubKey = ((X25519PrivateKeyParameters)xdhPrivateKey).generatePublicKey();
        }
        return Utils.keyToString("Private Key", getAlgorithm(), pubKey);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof PrivateKey))
        {
            return false;
        }

        PrivateKey other = (PrivateKey)o;

        return Arrays.areEqual(other.getEncoded(), this.getEncoded());
    }

    public int hashCode()
    {
        return Arrays.hashCode(this.getEncoded());
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        populateFromPrivateKeyInfo(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}