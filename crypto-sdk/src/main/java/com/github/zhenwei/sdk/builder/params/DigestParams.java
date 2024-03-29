package com.github.zhenwei.sdk.builder.params;

import com.github.zhenwei.core.exception.WeGooKeyException;
import com.github.zhenwei.core.util.encoders.Hex;
import com.github.zhenwei.sdk.builder.KeyBuilder;
import java.security.PublicKey;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DigestParams {

  private PublicKey publicKey;

  // 1234567812345678
  private byte[] userID = Hex.decodeStrict("31323334353637383132333435363738");


  public DigestParams(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  public DigestParams(PublicKey publicKey, byte[] userID) {
    this.publicKey = publicKey;
    this.userID = userID;
  }

  public static DigestParams getInstance(Object data) throws WeGooKeyException {
    PublicKey publicKey = null;
    if (data instanceof PublicKey) {
      publicKey = (PublicKey) data;
    } else if (data instanceof byte[]) {
      publicKey = KeyBuilder.convertPublicKey((byte[]) data);
    }
    return new DigestParams(publicKey);
  }

}