package com.github.zhenwei.pkix.util.oer.its;

import java.io.IOException;
import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.DEROctetString;

public class SubjectAssurance
    extends DEROctetString
{

    public SubjectAssurance(byte[] string)
    {
        super(string);
    }


    public SubjectAssurance(ASN1Encodable obj)
        throws IOException
    {
        super(obj);
    }

    public static SubjectAssurance getInstance(Object o)
    {
        if (o instanceof SubjectAssurance)
        {
            return (SubjectAssurance)o;
        }
        else
        {
            return new SubjectAssurance(DEROctetString.getInstance(o).getOctets());
        }
    }
}