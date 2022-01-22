package com.github.zhenwei.sdk.util.asn1.crmf;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERBitString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.sdk.util.asn1.cmp.CMPObjectIdentifiers;
import com.github.zhenwei.sdk.util.asn1.cmp.PBMParameter;

/**
 * Password-based MAC value for use with POPOSigningKeyInput.
 */
public class PKMACValue
    extends ASN1Object
{
    private AlgorithmIdentifier algId;
    private DERBitString value;

    private PKMACValue(ASN1Sequence seq)
    {
        algId = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        value = DERBitString.getInstance(seq.getObjectAt(1));
    }

    public static crmf.PKMACValue getInstance(Object o)
    {
        if (o instanceof crmf.PKMACValue)
        {
            return (crmf.PKMACValue)o;
        }

        if (o != null)
        {
            return new crmf.PKMACValue(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static crmf.PKMACValue getInstance(ASN1TaggedObject obj, boolean isExplicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, isExplicit));
    }

    /**
     * Creates a new PKMACValue.
     * @param params parameters for password-based MAC
     * @param value MAC of the DER-encoded SubjectPublicKeyInfo
     */
    public PKMACValue(
        PBMParameter params,
        DERBitString value)
    {
        this(new AlgorithmIdentifier(
                    CMPObjectIdentifiers.passwordBasedMac, params), value);
    }

    /**
     * Creates a new PKMACValue.
     * @param aid CMPObjectIdentifiers.passwordBasedMAC, with PBMParameter
     * @param value MAC of the DER-encoded SubjectPublicKeyInfo
     */
    public PKMACValue(
        AlgorithmIdentifier aid,
        DERBitString value)
    {
        this.algId = aid;
        this.value = value;
    }

    public AlgorithmIdentifier getAlgId()
    {
        return algId;
    }

    public DERBitString getValue()
    {
        return value;
    }

    /**
     * <pre>
     * PKMACValue ::= SEQUENCE {
     *      algId  AlgorithmIdentifier,
     *      -- algorithm value shall be PasswordBasedMac 1.2.840.113533.7.66.13
     *      -- parameter value is PBMParameter
     *      value  BIT STRING }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(algId);
        v.add(value);

        return new DERSequence(v);
    }
}