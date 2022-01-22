package com.github.zhenwei.pkix.util.asn1.icao;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERSet;

/**
 * The CscaMasterList object. This object can be wrapped in a
 * CMSSignedData to be published in LDAP.
 *
 * <pre>
 * CscaMasterList ::= SEQUENCE {
 *   version                CscaMasterListVersion,
 *   certList               SET OF Certificate }
 *
 * CscaMasterListVersion :: INTEGER {v0(0)}
 * </pre>
 */

public class CscaMasterList
    extends ASN1Object
{
    private ASN1Integer version = new ASN1Integer(0);
    private Certificate[] certList;

    public static icao.CscaMasterList getInstance(
        Object obj)
    {
        if (obj instanceof icao.CscaMasterList)
        {
            return (icao.CscaMasterList)obj;
        }
        else if (obj != null)
        {
            return new icao.CscaMasterList(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private CscaMasterList(
        ASN1Sequence seq)
    {
        if (seq == null || seq.size() == 0)
        {
            throw new IllegalArgumentException(
                "null or empty sequence passed.");
        }
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException(
                "Incorrect sequence size: " + seq.size());
        }

        version = ASN1Integer.getInstance(seq.getObjectAt(0));
        ASN1Set certSet = ASN1Set.getInstance(seq.getObjectAt(1));
        certList = new Certificate[certSet.size()];
        for (int i = 0; i < certList.length; i++)
        {
            certList[i]
                = Certificate.getInstance(certSet.getObjectAt(i));
        }
    }

    public CscaMasterList(
        Certificate[] certStructs)
    {
        certList = copyCertList(certStructs);
    }

    public int getVersion()
    {
        return version.intValueExact();
    }

    public Certificate[] getCertStructs()
    {
        return copyCertList(certList);
    }

    private Certificate[] copyCertList(Certificate[] orig)
    {
        Certificate[] certs = new Certificate[orig.length];

        for (int i = 0; i != certs.length; i++)
        {
            certs[i] = orig[i];
        }

        return certs;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector seq = new ASN1EncodableVector(2);

        seq.add(version);
        seq.add(new DERSet(certList));

        return new DERSequence(seq);
    }
}