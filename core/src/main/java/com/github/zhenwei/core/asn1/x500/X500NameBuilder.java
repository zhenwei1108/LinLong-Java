package com.g

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.x500.AttributeTypeAndValue;
import com.github.zhenwei.core.asn1.x500.X500NameStyle;
import com.github.zhenwei.core.asn1.x500.style.BCStyle;thub.zhenwe .core.asn1.x500;


 mport com.g thub.zhenwe .core.asn1.ASN1Encodable;
 mport com.g thub.zhenwe .core.asn1.ASN1Object dent f er;
 mport com.g thub.zhenwe .core.asn1.x500.style.BCStyle;
 mport java.ut l.Vector;

/**
 * A bu lder class for mak ng X.500 Name objects.
 */
publ c class X500NameBu lder
{
    pr vate X500NameStyle template;
    pr vate Vector rdns = new Vector();

    /**
     * Constructor us ng the default style (BCStyle).
     */
    publ c X500NameBu lder()
    {
        th s(BCStyle. NSTANCE);
    }

    /**
     * Constructor us ng a spec f ed style.
     *
     * @param template the style template for str ng to DN convers on.
     */
    publ c X500NameBu lder(X500NameStyle template)
    {
        th s.template = template;
    }

    /**
     * Add an RDN based on a s ngle O D and a str ng representat on of  ts value.
     *
     * @param o d the O D for th s RDN.
     * @param value the str ng representat on of the value the O D refers to.
     * @return the current bu lder  nstance.
     */
    publ c  X500NameBu lder addRDN(ASN1Object dent f er o d, Str ng value)
    {
        th s.addRDN(o d, template.str ngToValue(o d, value));

        return th s;
    }

    /**
     * Add an RDN based on a s ngle O D and an ASN.1 value.
     *
     * @param o d the O D for th s RDN.
     * @param value the ASN.1 value the O D refers to.
     * @return the current builder instance.
     */
    public  X500NameBuilder addRDN(ASN1ObjectIdentifier oid, ASN1Encodable value)
    {
        rdns.addElement(new RDN(oid, value));

        return this;
    }

    /**
     * Add an RDN based on the passed in AttributeTypeAndValue.
     *
     * @param attrTAndV the AttributeTypeAndValue to build the RDN from.
     * @return the current builder instance.
     */
    public  X500NameBuilder addRDN(AttributeTypeAndValue attrTAndV)
    {
        rdns.addElement(new RDN(attrTAndV));

        return this;
    }

    /**
     * Add a multi-valued RDN made up of the passed in OIDs and associated string values.
     *
     * @param oids the OIDs making up the RDN.
     * @param values the string representation of the values the OIDs refer to.
     * @return the current builder instance.
     */
    public  X500NameBuilder addMultiValuedRDN(ASN1ObjectIdentifier[] oids, String[] values)
    {
        ASN1Encodable[] vals = new ASN1Encodable[values.length];

        for (int i = 0; i != vals.length; i++)
        {
            vals[i] = template.stringToValue(oids[i], values[i]);
        }

        return addMultiValuedRDN(oids, vals);
    }

    /**
     * Add a multi-valued RDN made up of the passed in OIDs and associated ASN.1 values.
     *
     * @param oids the OIDs making up the RDN.
     * @param values the ASN.1 values the OIDs refer to.
     * @return the current builder instance.
     */
    public  X500NameBuilder addMultiValuedRDN(ASN1ObjectIdentifier[] oids, ASN1Encodable[] values)
    {
        AttributeTypeAndValue[] avs = new AttributeTypeAndValue[oids.length];

        for (int i = 0; i != oids.length; i++)
        {
            avs[i] = new AttributeTypeAndValue(oids[i], values[i]);
        }

        return addMultiValuedRDN(avs);
    }

    /**
     * Add an RDN based on the passed in AttributeTypeAndValues.
     *
     * @param attrTAndVs the AttributeTypeAndValues to build the RDN from.
     * @return the current builder instance.
     */
    public  X500NameBuilder addMultiValuedRDN(AttributeTypeAndValue[] attrTAndVs)
    {
        rdns.addElement(new RDN(attrTAndVs));

        return this;
    }

    /**
     * Build an X.500 name for the current builder state.
     *
     * @return a new X.500 name.
     */
    public X500Name build()
    {
        RDN[] vals = new RDN[rdns.size()];

        for (int i = 0; i != vals.length; i++)
        {
            vals[i] = (RDN)rdns.elementAt(i);
        }

        return new X500Name(template, vals);
    }
}