package com.github.zhenwei.pkix.util.asn1.cmp;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERTaggedObject;
import com.github.zhenwei.core.asn1.x509.CertificateList;
import com.github.zhenwei.pkix.util.asn1.crmf.CertId;

public class RevRepContentBuilder {

  private ASN1EncodableVector status = new ASN1EncodableVector();
  private ASN1EncodableVector revCerts = new ASN1EncodableVector();
  private ASN1EncodableVector crls = new ASN1EncodableVector();

  public RevRepContentBuilder add(PKIStatusInfo status) {
    this.status.add(status);

    return this;
  }

  public RevRepContentBuilder add(PKIStatusInfo status, CertId certId) {
    if (this.status.size() != this.revCerts.size()) {
      throw new IllegalStateException("status and revCerts sequence must be in common order");
    }
    this.status.add(status);
    this.revCerts.add(certId);

    return this;
  }

  public RevRepContentBuilder addCrl(CertificateList crl) {
    this.crls.add(crl);

    return this;
  }

  public RevRepContent build() {
    ASN1EncodableVector v = new ASN1EncodableVector(3);

    v.add(new DERSequence(status));

    if (revCerts.size() != 0) {
      v.add(new DERTaggedObject(true, 0, new DERSequence(revCerts)));
    }

    if (crls.size() != 0) {
      v.add(new DERTaggedObject(true, 1, new DERSequence(crls)));
    }

    return RevRepContent.getInstance(new DERSequence(v));
  }
}