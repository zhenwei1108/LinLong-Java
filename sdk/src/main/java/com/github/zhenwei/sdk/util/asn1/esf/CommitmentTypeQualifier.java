package com.github.zhenwei.sdk.util.asn1.esf;









/**
 * Commitment type qualifiers, used in the Commitment-Type-Indication attribute (RFC3126).
 * 
 * <pre>
 *   CommitmentTypeQualifier ::= SEQUENCE {
 *       commitmentTypeIdentifier  CommitmentTypeIdentifier,
 *       qualifier          ANY DEFINED BY commitmentTypeIdentifier OPTIONAL }
 * </pre>
 */
public class CommitmentTypeQualifier
    extends ASN1Object
{
   private ASN1ObjectIdentifier commitmentTypeIdentifier;
   private ASN1Encodable qualifier;

   /**
    * Creates a new <code>CommitmentTypeQualifier</code> instance.
    *
    * @param commitmentTypeIdentifier a <code>CommitmentTypeIdentifier</code> value
    */
    public CommitmentTypeQualifier(
        ASN1ObjectIdentifier commitmentTypeIdentifier)
    {
        this(commitmentTypeIdentifier, null);
    }
    
   /**
    * Creates a new <code>CommitmentTypeQualifier</code> instance.
    *
    * @param commitmentTypeIdentifier a <code>CommitmentTypeIdentifier</code> value
    * @param qualifier the qualifier, defined by the above field.
    */
    public CommitmentTypeQualifier(
        ASN1ObjectIdentifier commitmentTypeIdentifier,
        ASN1Encodable qualifier)
    {
        this.commitmentTypeIdentifier = commitmentTypeIdentifier;
        this.qualifier = qualifier;
    }

    /**
     * Creates a new <code>CommitmentTypeQualifier</code> instance.
     *
     * @param as <code>CommitmentTypeQualifier</code> structure
     * encoded as an ASN1Sequence. 
     */
    private CommitmentTypeQualifier(
        ASN1Sequence as)
    {
        commitmentTypeIdentifier = (ASN1ObjectIdentifier)as.getObjectAt(0);
        
        if (as.size() > 1)
        {
            qualifier = as.getObjectAt(1);
        }
    }

    public static esf.CommitmentTypeQualifier getInstance(Object as)
    {
        if (as instanceof esf.CommitmentTypeQualifier)
        {
            return (esf.CommitmentTypeQualifier)as;
        }
        else if (as != null)
        {
            return new esf.CommitmentTypeQualifier(ASN1Sequence.getInstance(as));
        }

        return null;
    }

    public ASN1ObjectIdentifier getCommitmentTypeIdentifier()
    {
        return commitmentTypeIdentifier;
    }
    
    public ASN1Encodable getQualifier()
    {
        return qualifier;
    }

   /**
    * Returns a DER-encodable representation of this instance. 
    *
    * @return a <code>ASN1Primitive</code> value
    */
   public ASN1Primitive toASN1Primitive()
   {
      ASN1EncodableVector dev = new ASN1EncodableVector(2);
      dev.add(commitmentTypeIdentifier);
      if (qualifier != null)
      {
          dev.add(qualifier);
      }

      return new DERSequence(dev);
   }
}