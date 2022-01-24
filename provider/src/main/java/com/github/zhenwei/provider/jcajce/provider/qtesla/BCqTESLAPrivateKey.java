package com.github.zhenwei.provider.jcajce.provider.qtesla;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import com.github.zhenwei.core.pqc.crypto.qtesla.QTESLASecurityCategory;
import com.github.zhenwei.core.pqc.crypto.util.PrivateKeyFactory;
import com.github.zhenwei.core.pqc.crypto.util.PrivateKeyInfoFactory;
import com.github.zhenwei.provider.jcajce.interfaces.QTESLAKey;
import com.github.zhenwei.provider.jcajce.spec.QTESLAParameterSpec;
import com.github.zhenwei.core.util.Arrays;

public class BCqTESLAPrivateKey
    implements PrivateKey, QTESLAKey
{
    private static final long serialVersionUID = 1L;

    private transient QTESLAPrivateKeyParameters keyParams;
    private transient ASN1Set attributes;

    public BCqTESLAPrivateKey(
        QTESLAPrivateKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    public BCqTESLAPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.keyParams = (QTESLAPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    /**
     * @return name of the algorithm
     */
    public final String getAlgorithm()
    {
        return QTESLASecurityCategory.getName(keyParams.getSecurityCategory());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public QTESLAParameterSpec getParams()
    {
        return new QTESLAParameterSpec(getAlgorithm());
    }

    public byte[] getEncoded()
    {
        PrivateKeyInfo pki;
        try
        {
            pki = PrivateKeyInfoFactory.createPrivateKeyInfo(keyParams, attributes);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCqTESLAPrivateKey)
        {
            BCqTESLAPrivateKey otherKey = (BCqTESLAPrivateKey)o;

            return keyParams.getSecurityCategory() == otherKey.keyParams.getSecurityCategory()
                && Arrays.areEqual(keyParams.getSecret(), otherKey.keyParams.getSecret());
        }

        return false;
    }

    public int hashCode()
    {
        return keyParams.getSecurityCategory() + 37 * Arrays.hashCode(keyParams.getSecret());
    }

    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}