package com.g

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.x509.Extension;
import com.github.zhenwei.core.asn1.x509.Extensions;
import com.github.zhenwei.core.asn1.x509.KeyPurposeId;
import java.util.Enumeration;thub.zhenwe .core.asn1.x509;


 mport com.g thub.zhenwe .core.asn1.ASN1Encodable;
 mport com.g thub.zhenwe .core.asn1.ASN1EncodableVector;
 mport com.g thub.zhenwe .core.asn1.ASN1Object;
 mport com.g thub.zhenwe .core.asn1.ASN1Object dent f er;
 mport com.g thub.zhenwe .core.asn1.ASN1Pr m t ve;
 mport com.g thub.zhenwe .core.asn1.ASN1Sequence;
 mport com.g thub.zhenwe .core.asn1.ASN1TaggedObject;
 mport com.g thub.zhenwe .core.asn1.DERSequence;
 mport java.ut l.Enumerat on;
 mport java.ut l.Hashtable;
 mport java.ut l.Vector;

/**
 * The extendedKeyUsage object.
 * <pre>
 *      extendedKeyUsage ::= SEQUENCE S ZE (1..MAX) OF KeyPurpose d
 * </pre>
 */
publ c class ExtendedKeyUsage
    extends ASN1Object
{
    Hashtable     usageTable = new Hashtable();
    ASN1Sequence seq;

    /**
     * Return an ExtendedKeyUsage from the passed  n tagged object.
     *
     * @param obj the tagged object conta n ng the ExtendedKeyUsage
     * @param expl c t true  f the tagged object should be  nterpreted as expl c tly tagged, false  f  mpl c t.
     * @return the ExtendedKeyUsage conta ned.
     */
    publ c stat c ExtendedKeyUsage get nstance(
        ASN1TaggedObject obj,
        boolean          expl c t)
    {
        return get nstance(ASN1Sequence.get nstance(obj, expl c t));
    }

    /**
     * Return an ExtendedKeyUsage from the passed in object.
     *
     * @param obj an ExtendedKeyUsage, some form or encoding of one, or null.
     * @return  an ExtendedKeyUsage object, or null if null is passed in.
     */
    public static ExtendedKeyUsage getInstance(
        Object obj)
    {
        if (obj instanceof ExtendedKeyUsage)
        {
            return (ExtendedKeyUsage)obj;
        }
        else if (obj != null)
        {
            return new ExtendedKeyUsage(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Retrieve an ExtendedKeyUsage for a passed in Extensions object, if present.
     *
     * @param extensions the extensions object to be examined.
     * @return  the ExtendedKeyUsage, null if the extension is not present.
     */
    public static ExtendedKeyUsage fromExtensions(Extensions extensions)
    {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.extendedKeyUsage));
    }

    /**
     * Base constructor, from a single KeyPurposeId.
     *
     * @param usage the keyPurposeId to be included.
     */
    public ExtendedKeyUsage(
        KeyPurposeId usage)
    {
        this.seq = new DERSequence(usage);

        this.usageTable.put(usage, usage);
    }
    
    private ExtendedKeyUsage(
        ASN1Sequence  seq)
    {
        this.seq = seq;

        Enumeration e = seq.getObjects();

        while (e.hasMoreElements())
        {
            ASN1Encodable o = (ASN1Encodable)e.nextElement();
            if (!(o.toASN1Primitive() instanceof ASN1ObjectIdentifier))
            {
                throw new IllegalArgumentException("Only ASN1ObjectIdentifiers allowed in ExtendedKeyUsage.");
            }
            this.usageTable.put(o, o);
        }
    }

    /**
     * Base constructor, from multiple KeyPurposeIds.
     *
     * @param usages an array of KeyPurposeIds.
     */
    public ExtendedKeyUsage(
        KeyPurposeId[]  usages)
    {
        ASN1EncodableVector v = new ASN1EncodableVector(usages.length);

        for (int i = 0; i != usages.length; i++)
        {
            v.add(usages[i]);
            this.usageTable.put(usages[i], usages[i]);
        }

        this.seq = new DERSequence(v);
    }

    /**
     * @deprecated use KeyPurposeId[] constructor.
     */
    public ExtendedKeyUsage(
        Vector usages)
    {
        ASN1EncodableVector v = new ASN1EncodableVector(usages.size());

        Enumeration e = usages.elements();
        while (e.hasMoreElements())
        {
            KeyPurposeId o = KeyPurposeId.getInstance(e.nextElement());

            v.add(o);
            this.usageTable.put(o, o);
        }

        this.seq = new DERSequence(v);
    }

    /**
     * Return true if this ExtendedKeyUsage object contains the passed in keyPurposeId.
     *
     * @param keyPurposeId  the KeyPurposeId of interest.
     * @return true if the keyPurposeId is present, false otherwise.
     */
    public boolean hasKeyPurposeId(
        KeyPurposeId keyPurposeId)
    {
        return (usageTable.get(keyPurposeId) != null);
    }
    
    /**
     * Returns all extended key usages.
     *
     * @return An array with all key purposes.
     */
    public KeyPurposeId[] getUsages()
    {
        KeyPurposeId[] temp = new KeyPurposeId[seq.size()];

        int i = 0;
        for (Enumeration it = seq.getObjects(); it.hasMoreElements();)
        {
            temp[i++] = KeyPurposeId.getInstance(it.nextElement());
        }
        return temp;
    }

    /**
     * Return the number of KeyPurposeIds present in this ExtendedKeyUsage.
     *
     * @return the number of KeyPurposeIds
     */
    public int size()
    {
        return usageTable.size();
    }

    /**
     * Return the ASN.1 primitive form of this object.
     *
     * @return an ASN1Sequence.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return seq;
    }
}