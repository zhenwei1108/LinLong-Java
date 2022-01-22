package com.github.zhenwei.pkix.util.oer.its;


import com.github.zhenwei.core.asn1.ASN1Choice;
import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERTaggedObject;

/**
 * IdentifiedRegion ::= CHOICE {
 * countryOnly           CountryOnly,
 * countryAndRegions     CountryAndRegions,
 * countryAndSubregions  CountryAndSubregions,
 * ...
 * }
 */
public class IdentifiedRegion
    extends ASN1Object
    implements ASN1Choice, RegionInterface
{

    public static final int countryOnly = 0;
    public static final int countryAndRegions = 1;
    public static final int countAndSubregions = 2;
    public static final int extension = 3;

    private int choice;
    private ASN1Encodable region;

    public IdentifiedRegion(int choice, ASN1Encodable region)
    {
        this.choice = choice;
        this.region = region;
    }

    public static IdentifiedRegion getInstance(Object o)
    {
        if (o instanceof IdentifiedRegion)
        {
            return (IdentifiedRegion)o;
        }
        else
        {
            ASN1TaggedObject asn1TaggedObject = ASN1TaggedObject.getInstance(o);

            int choice = asn1TaggedObject.getTagNo();

            o = asn1TaggedObject.getObject();
            switch (choice)
            {
            case countryOnly:
                return new IdentifiedRegion(choice, CountryOnly.getInstance(o));
            case countryAndRegions:
                return new IdentifiedRegion(choice, CountryAndRegions.getInstance(o));
            case countAndSubregions:
                return new IdentifiedRegion(choice, RegionAndSubregions.getInstance(o));
            case extension:
                return new IdentifiedRegion(choice, DEROctetString.getInstance(o));
            default:
                throw new IllegalArgumentException("unknown choice " + choice);
            }


        }
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, (ASN1Object)region).toASN1Primitive();
    }
}