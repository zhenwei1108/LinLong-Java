package com.github.zhenwei.core.asn1.misc;




public class VerisignCzagExtension
    extends DERIA5String
{
    public VerisignCzagExtension(
        ASN1IA5String str)
    {
        super(str.getString());
    }

    public String toString()
    {
        return "VerisignCzagExtension: " + this.getString();
    }
}