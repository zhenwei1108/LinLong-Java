package com.github.zhenwei.pkix.dvcs;

import com.github.zhenwei.core.asn1.x509.DigestInfo;

public class MessageImprint {

  private final DigestInfo messageImprint;

  public MessageImprint(DigestInfo messageImprint) {
    this.messageImprint = messageImprint;
  }

  public DigestInfo toASN1Structure() {
    return messageImprint;
  }

  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }

    if (o instanceof MessageImprint) {
      return messageImprint.equals(((MessageImprint) o).messageImprint);
    }

    return false;
  }

  public int hashCode() {
    return messageImprint.hashCode();
  }
}