package com.github.zhenwei.sdk.util.oer.its;










import java.io.IOException;


/**
 * <pre>
 *     SubjectPermissions ::= CHOICE {
 *         explicit SequenceOfPsidSspRange,
 *         all NULL,
 *         ...
 *     }
 * </pre>
 */
public class SubjectPermissions
    extends ASN1Object
    implements ASN1Choice
{

    public static final int explicit = 0;
    public static final int all = 1;
    public static final int extension = 3;

    private final ASN1Encodable value;
    private final int choice;

    SubjectPermissions(int choice, ASN1Encodable value)
    {
        this.value = value;
        this.choice = choice;
    }

    public static SubjectPermissions getInstance(Object src)
    {
        if (src instanceof SubjectPermissions)
        {
            return (SubjectPermissions)src;
        }

        ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(src);
        int item = taggedObject.getTagNo();

        switch (item)
        {
        case explicit:
            return new SubjectPermissions(explicit,
                SequenceOfPsidSspRange.getInstance(taggedObject.getObject()));
        case all:
            return new SubjectPermissions(all, DERNull.INSTANCE);
        case extension:
            try
            {
                return new SubjectPermissions(extension, new DEROctetString(taggedObject.getObject().getEncoded()));
            }
            catch (IOException ioException)
            {
                throw new RuntimeException(ioException.getMessage(), ioException);
            }
        }

        return null;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, value);
    }

    public static class Builder
    {
        int choice;
        ASN1Encodable value;

        public Builder choice(int choice)
        {
            this.choice = choice;
            return this;
        }

        public Builder value(ASN1Encodable value)
        {
            this.value = value;
            return this;
        }


        public Builder explicit(SequenceOfPsidSspRange value)
        {
            this.choice = explicit;
            this.value = value;
            return this;
        }

        public Builder all()
        {
            this.choice = all;
            this.value = DERNull.INSTANCE;
            return this;
        }

        public Builder extension(ASN1Encodable encodable)
        {
            this.choice = extension;
            if (encodable instanceof ASN1OctetString)
            {
                value = encodable;
            }
            else
            {
                try
                {
                    value = new DEROctetString(encodable.toASN1Primitive().getEncoded());
                }
                catch (IOException ioException)
                {
                    throw new RuntimeException(ioException.getMessage(), ioException);
                }
            }
            return this;
        }

        public SubjectPermissions createSubjectPermissions()
        {
            return new SubjectPermissions(choice, value);
        }

    }

}