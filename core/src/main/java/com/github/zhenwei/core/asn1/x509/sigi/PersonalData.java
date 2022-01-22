package com.github.zhenwei.core.asn1.sigi;


import ASN1GeneralizedTime;










import java.math.BigInteger;
import java.util.Enumeration;
import sigi.NameOrPseudonym;

/**
 * Contains personal data for the otherName field in the subjectAltNames
 * extension.
 *
 * <pre>
 *     PersonalData ::= SEQUENCE {
 *       nameOrPseudonym NameOrPseudonym,
 *       nameDistinguisher [0] INTEGER OPTIONAL,
 *       dateOfBirth [1] GeneralizedTime OPTIONAL,
 *       placeOfBirth [2] DirectoryString OPTIONAL,
 *       gender [3] PrintableString OPTIONAL,
 *       postalAddress [4] DirectoryString OPTIONAL
 *       }
 * </pre>
 *
 * @see NameOrPseudonym
 * @see sigi.SigIObjectIdentifiers
 */
public class PersonalData
    extends ASN1Object
{
    private NameOrPseudonym nameOrPseudonym;
    private BigInteger nameDistinguisher;
    private ASN1GeneralizedTime dateOfBirth;
    private DirectoryString placeOfBirth;
    private String gender;
    private DirectoryString postalAddress;

    public static sigi.PersonalData getInstance(Object obj)
    {
        if (obj == null || obj instanceof sigi.PersonalData)
        {
            return (sigi.PersonalData)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new sigi.PersonalData((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Constructor from ASN1Sequence.
     * <p>
     * The sequence is of type NameOrPseudonym:
     * <pre>
     *     PersonalData ::= SEQUENCE {
     *       nameOrPseudonym NameOrPseudonym,
     *       nameDistinguisher [0] INTEGER OPTIONAL,
     *       dateOfBirth [1] GeneralizedTime OPTIONAL,
     *       placeOfBirth [2] DirectoryString OPTIONAL,
     *       gender [3] PrintableString OPTIONAL,
     *       postalAddress [4] DirectoryString OPTIONAL
     *       }
     * </pre>
     * </p>
     * @param seq The ASN.1 sequence.
     */
    private PersonalData(ASN1Sequence seq)
    {
        if (seq.size() < 1)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }

        Enumeration e = seq.getObjects();

        nameOrPseudonym = NameOrPseudonym.getInstance(e.nextElement());

        while (e.hasMoreElements())
        {
            ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
            int tag = o.getTagNo();
            switch (tag)
            {
                case 0:
                    nameDistinguisher = ASN1Integer.getInstance(o, false).getValue();
                    break;
                case 1:
                    dateOfBirth = ASN1GeneralizedTime.getInstance(o, false);
                    break;
                case 2:
                    placeOfBirth = DirectoryString.getInstance(o, true);
                    break;
                case 3:
                    gender = ASN1PrintableString.getInstance(o, false).getString();
                    break;
                case 4:
                    postalAddress = DirectoryString.getInstance(o, true);
                    break;
                default:
                    throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
            }
        }
    }

    /**
     * Constructor from a given details.
     *
     * @param nameOrPseudonym   Name or pseudonym.
     * @param nameDistinguisher Name distinguisher.
     * @param dateOfBirth       Date of birth.
     * @param placeOfBirth      Place of birth.
     * @param gender            Gender.
     * @param postalAddress     Postal Address.
     */
    public PersonalData(NameOrPseudonym nameOrPseudonym,
                        BigInteger nameDistinguisher, ASN1GeneralizedTime dateOfBirth,
                        DirectoryString placeOfBirth, String gender, DirectoryString postalAddress)
    {
        this.nameOrPseudonym = nameOrPseudonym;
        this.dateOfBirth = dateOfBirth;
        this.gender = gender;
        this.nameDistinguisher = nameDistinguisher;
        this.postalAddress = postalAddress;
        this.placeOfBirth = placeOfBirth;
    }

    public NameOrPseudonym getNameOrPseudonym()
    {
        return nameOrPseudonym;
    }

    public BigInteger getNameDistinguisher()
    {
        return nameDistinguisher;
    }

    public ASN1GeneralizedTime getDateOfBirth()
    {
        return dateOfBirth;
    }

    public DirectoryString getPlaceOfBirth()
    {
        return placeOfBirth;
    }

    public String getGender()
    {
        return gender;
    }

    public DirectoryString getPostalAddress()
    {
        return postalAddress;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <p>
     * Returns:
     * <pre>
     *     PersonalData ::= SEQUENCE {
     *       nameOrPseudonym NameOrPseudonym,
     *       nameDistinguisher [0] INTEGER OPTIONAL,
     *       dateOfBirth [1] GeneralizedTime OPTIONAL,
     *       placeOfBirth [2] DirectoryString OPTIONAL,
     *       gender [3] PrintableString OPTIONAL,
     *       postalAddress [4] DirectoryString OPTIONAL
     *       }
     * </pre>
     *
     * @return a DERObject
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vec = new ASN1EncodableVector(6);
        vec.add(nameOrPseudonym);
        if (nameDistinguisher != null)
        {
            vec.add(new DERTaggedObject(false, 0, new ASN1Integer(nameDistinguisher)));
        }
        if (dateOfBirth != null)
        {
            vec.add(new DERTaggedObject(false, 1, dateOfBirth));
        }
        if (placeOfBirth != null)
        {
            vec.add(new DERTaggedObject(true, 2, placeOfBirth));
        }
        if (gender != null)
        {
            vec.add(new DERTaggedObject(false, 3, new DERPrintableString(gender, true)));
        }
        if (postalAddress != null)
        {
            vec.add(new DERTaggedObject(true, 4, postalAddress));
        }
        return new DERSequence(vec);
    }
}