package com.github.zhenwei.provider.jcajce.provider.xmss;


import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import  SubjectPublicKeyInfo;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import com.github.zhenwei.core.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTKey;


public class BCXMSSMTPublicKey
    implements PublicKey, XMSSMTKey
{
    private static final long serialVersionUID = 3230324130542413475L;

    private transient ASN1ObjectIdentifier treeDigest;
    private transient XMSSMTPublicKeyParameters keyParams;

    public BCXMSSMTPublicKey(ASN1ObjectIdentifier treeDigest, XMSSMTPublicKeyParameters keyParams)
    {
        this.treeDigest = treeDigest;
        this.keyParams = keyParams;
    }

    public BCXMSSMTPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.keyParams = (XMSSMTPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
        this.treeDigest =  DigestUtil.getDigestOID(this.keyParams.getTreeDigest());
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPublicKey)
        {
            org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPublicKey otherKey = (org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPublicKey)o;

            return treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(keyParams.toByteArray(), otherKey.keyParams.toByteArray());
        }

        return false;
    }

    public int hashCode()
    {
        return treeDigest.hashCode() + 37 * Arrays.hashCode(keyParams.toByteArray());
    }

    /**
     * @return name of the algorithm - "XMSSMT"
     */
    public final String getAlgorithm()
    {
        return "XMSSMT";
    }

    public byte[] getEncoded()
    {
        try
        {
            SubjectPublicKeyInfo pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyParams);

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

    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    public int getHeight()
    {
        return keyParams.getParameters().getHeight();
    }

    public int getLayers()
    {
        return keyParams.getParameters().getLayers();
    }

    public String getTreeDigest()
    {
        return DigestUtil.getXMSSDigestName(treeDigest);
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