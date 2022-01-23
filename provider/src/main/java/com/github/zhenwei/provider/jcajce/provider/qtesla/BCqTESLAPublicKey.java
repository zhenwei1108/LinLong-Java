package com.github.zhenwei.provider.jcajce.provider.qtesla;


import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import com.github.zhenwei.core.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
  
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.QTESLAKey;
import org.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;


public class BCqTESLAPublicKey
    implements PublicKey, QTESLAKey
{
    private static final long serialVersionUID = 1L;

    private transient QTESLAPublicKeyParameters keyParams;

    public BCqTESLAPublicKey(
        QTESLAPublicKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    public BCqTESLAPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.keyParams = (QTESLAPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
    }

    /**
     * @return name of the algorithm
     */
    public final String getAlgorithm()
    {
        return QTESLASecurityCategory.getName(keyParams.getSecurityCategory());
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

    public QTESLAParameterSpec getParams()
    {
        return new QTESLAParameterSpec(getAlgorithm());
    }
    
    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof org.bouncycastle.pqc.jcajce.provider.qtesla.BCqTESLAPublicKey)
        {
            org.bouncycastle.pqc.jcajce.provider.qtesla.BCqTESLAPublicKey otherKey = (org.bouncycastle.pqc.jcajce.provider.qtesla.BCqTESLAPublicKey)o;

            return keyParams.getSecurityCategory() == otherKey.keyParams.getSecurityCategory()
                && Arrays.areEqual(keyParams.getPublicData(), otherKey.keyParams.getPublicData());
        }

        return false;
    }

    public int hashCode()
    {
        return keyParams.getSecurityCategory() + 37 * Arrays.hashCode(keyParams.getPublicData());
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