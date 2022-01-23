package com.github.zhenwei.provider.jcajce.provider.asymmetric.edec;


import com.github.zhenwei.core.asn1.edec.EdECObjectIdentifiers;
import  SubjectPublicKeyInfo;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
 
 
import  interfaces.EdDSAPublicKey;


public class BCEdDSAPublicKey
    implements EdDSAPublicKey
{
    static final long serialVersionUID = 1L;

    transient AsymmetricKeyParameter eddsaPublicKey;

    BCEdDSAPublicKey(AsymmetricKeyParameter pubKey)
    {
        this.eddsaPublicKey = pubKey;
    }

    BCEdDSAPublicKey(SubjectPublicKeyInfo keyInfo)
    {
        populateFromPubKeyInfo(keyInfo);
    }

    BCEdDSAPublicKey(byte[] prefix, byte[] rawData)
        throws InvalidKeySpecException
    {
        int prefixLength = prefix.length;

        if (Utils.isValidPrefix(prefix, rawData))
        {
            if ((rawData.length - prefixLength) == Ed448PublicKeyParameters.KEY_SIZE)
            {
                eddsaPublicKey = new Ed448PublicKeyParameters(rawData, prefixLength);
            }
            else if ((rawData.length - prefixLength) == Ed25519PublicKeyParameters.KEY_SIZE)
            {
                eddsaPublicKey = new Ed25519PublicKeyParameters(rawData, prefixLength);
            }
            else
            {
                throw new InvalidKeySpecException("raw key data not recognised");
            }
        }
        else
        {
            throw new InvalidKeySpecException("raw key data not recognised");
        }
    }

    public byte[] getPointEncoding()
    {
        if (eddsaPublicKey instanceof Ed448PublicKeyParameters)
        {
            return ((Ed448PublicKeyParameters)eddsaPublicKey).getEncoded();
        }
        else
        {
            return ((Ed25519PublicKeyParameters)eddsaPublicKey).getEncoded();
        }
    }

    private void populateFromPubKeyInfo(SubjectPublicKeyInfo keyInfo)
    {
        byte[] encoding = keyInfo.getPublicKeyData().getOctets();

        if (EdECObjectIdentifiers.id_Ed448.equals(keyInfo.getAlgorithm().getAlgorithm()))
        {
            eddsaPublicKey = new Ed448PublicKeyParameters(encoding);
        }
        else
        {
            eddsaPublicKey = new Ed25519PublicKeyParameters(encoding);
        }
    }

    public String getAlgorithm()
    {
        return (eddsaPublicKey instanceof Ed448PublicKeyParameters) ? "Ed448" : "Ed25519";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        if (eddsaPublicKey instanceof Ed448PublicKeyParameters)
        {
            byte[] encoding = new byte[KeyFactorySpi.Ed448Prefix.length + Ed448PublicKeyParameters.KEY_SIZE];

            System.arraycopy(KeyFactorySpi.Ed448Prefix, 0, encoding, 0, KeyFactorySpi.Ed448Prefix.length);

            ((Ed448PublicKeyParameters)eddsaPublicKey).encode(encoding, KeyFactorySpi.Ed448Prefix.length);

            return encoding;
        }
        else
        {
            byte[] encoding = new byte[KeyFactorySpi.Ed25519Prefix.length + Ed25519PublicKeyParameters.KEY_SIZE];

            System.arraycopy(KeyFactorySpi.Ed25519Prefix, 0, encoding, 0, KeyFactorySpi.Ed25519Prefix.length);

            ((Ed25519PublicKeyParameters)eddsaPublicKey).encode(encoding, KeyFactorySpi.Ed25519Prefix.length);

            return encoding;
        }
    }

    AsymmetricKeyParameter engineGetKeyParameters()
    {
        return eddsaPublicKey;
    }

    public String toString()
    {
        return Utils.keyToString("Public Key", getAlgorithm(), eddsaPublicKey);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof PublicKey))
        {
            return false;
        }

        PublicKey other = (PublicKey)o;

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

        populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}