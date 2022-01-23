package com.github.zhenwei.provider.jcajce.provider.newhope;


import  SubjectPublicKeyInfo;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.pqc.crypto.newhope.NHPublicKeyParameters;
import com.github.zhenwei.core.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.NHPublicKey;


public class BCNHPublicKey
    implements NHPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient NHPublicKeyParameters params;

    public BCNHPublicKey(
        NHPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCNHPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (NHPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this SPHINCS-256 public key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (o == null || !(o instanceof org.bouncycastle.pqc.jcajce.provider.newhope.BCNHPublicKey))
        {
            return false;
        }
        org.bouncycastle.pqc.jcajce.provider.newhope.BCNHPublicKey otherKey = (org.bouncycastle.pqc.jcajce.provider.newhope.BCNHPublicKey)o;

        return Arrays.areEqual(params.getPubData(), otherKey.params.getPubData());
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getPubData());
    }

    /**
     * @return name of the algorithm - "NH"
     */
    public final String getAlgorithm()
    {
        return "NH";
    }

    public byte[] getEncoded()
    {
        try
        {
            SubjectPublicKeyInfo pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getPublicData()
    {
        return params.getPubData();
    }

    CipherParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
         ObjectInputStream in)
         throws IOException, ClassNotFoundException
     {
         in.defaultReadObject();

         byte[] enc = (byte[])in.readObject();

         init(SubjectPublicKeyInfo.getInstance(enc));
     }

     private void writeObject(
         ObjectOutputStream out)
         throws IOException
     {
         out.defaultWriteObject();

         out.writeObject(this.getEncoded());
     }
}