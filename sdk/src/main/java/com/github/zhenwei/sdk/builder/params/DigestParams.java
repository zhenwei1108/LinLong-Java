package com.github.zhenwei.sdk.builder.params;

import com.github.zhenwei.core.util.encoders.Hex;
import java.security.PublicKey;

public class DigestParams {

  private PublicKey publicKey;

  // 1234567812345678
  private byte[] userID = Hex.decodeStrict("31323334353637383132333435363738");

  public PublicKey getPublicKey() {
    return publicKey;
  }

  public void setPublicKey(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  public byte[] getUserID() {
    return userID;
  }

  public void setUserID(byte[] userID) {
    this.userID = userID;
  }

  public DigestParams(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  public DigestParams(PublicKey publicKey, byte[] userID) {
    this.publicKey = publicKey;
    this.userID = userID;
  }
}