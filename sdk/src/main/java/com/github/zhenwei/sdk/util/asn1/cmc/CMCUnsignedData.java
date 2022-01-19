package com.github.zhenwei.sdk.util.asn1.cmc;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.BodyPartPath;

/**
 * <pre>
 *      id-aa-cmc-unsignedData OBJECT IDENTIFIER ::= {id-aa 34}
 *
 *      CMCUnsignedData ::= SEQUENCE {
 *             bodyPartPath        BodyPartPath,
 *             identifier          OBJECT IDENTIFIER,
 *             content             ANY DEFINED BY identifier
 *      }
 * </pre>
 */
public class CMCUnsignedData
    extends ASN1Object
{
    private final BodyPartPath bodyPartPath;
    private final ASN1ObjectIdentifier identifier;
    private final ASN1Encodable content;

    public CMCUnsignedData(BodyPartPath bodyPartPath, ASN1ObjectIdentifier identifier, ASN1Encodable content)
    {
        this.bodyPartPath = bodyPartPath;
        this.identifier = identifier;
        this.content = content;
    }

    private CMCUnsignedData(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.bodyPartPath = BodyPartPath.getInstance(seq.getObjectAt(0));
        this.identifier = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
        this.content = seq.getObjectAt(2);
    }

    public static org.bouncycastle.asn1.cmc.CMCUnsignedData getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.asn1.cmc.CMCUnsignedData)
        {
            return (org.bouncycastle.asn1.cmc.CMCUnsignedData)o;
        }

        if (o != null)
        {
            return new org.bouncycastle.asn1.cmc.CMCUnsignedData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(bodyPartPath);
        v.add(identifier);
        v.add(content);

        return new DERSequence(v);
    }

    public BodyPartPath getBodyPartPath()
    {
        return bodyPartPath;
    }

    public ASN1ObjectIdentifier getIdentifier()
    {
        return identifier;
    }

    public ASN1Encodable getContent()
    {
        return content;
    }
}