package com.github.zhenwei.core.asn1.x509;

import java.util.Vector;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

public class GeneralNamesBuilder
{
    private Vector names = new Vector();

    public org.bouncycastle.asn1.x509.GeneralNamesBuilder addNames(GeneralNames names)
    {
        GeneralName[] n = names.getNames();

        for (int i = 0; i != n.length; i++)
        {
            this.names.addElement(n[i]);
        }

        return this;
    }

    public org.bouncycastle.asn1.x509.GeneralNamesBuilder addName(GeneralName name)
    {
        names.addElement(name);

        return this;
    }

    public GeneralNames build()
    {
        GeneralName[] tmp = new GeneralName[names.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = (GeneralName)names.elementAt(i);
        }

        return new GeneralNames(tmp);
    }
}