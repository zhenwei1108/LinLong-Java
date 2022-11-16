package com.github.zhenwei.core.asn1.sm2;

import com.github.zhenwei.core.asn1.ASN1BitString;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;

/**
 * @author: zhangzhenwei
 * @description: Sm2EnvelopedKey
 *  SM2 密钥对保护结构 GMT-0009#7.4
 *  SM2EnvelopedKey::=SEQUENCE(
 *    symAlgID   AlgorithmIdentifier, 算法标识
 *    symEncryptedKey  SM2Cipher,   公钥加密的  对称密钥
 *    Sm2PublicKey   sm2PublicKey, 公钥
 *    Sm2EncryptedPrivateKey BIT STRING   对称加密的 私钥
 * }
 * @date: 2022/10/20  11:25
 * @since: 1.0
 */
public class Sm2EnvelopedKey extends ASN1Object {

  private AlgorithmIdentifier symAlgId;
  //公钥加密的  对称密钥
  private Sm2Cipher sm2Cipher;
  /**
   * SM2PublicKey ::= BIT STRING
   */
  private ASN1BitString sm2PublicKey;
  // 对称加密的 私钥
  private ASN1BitString sm2EncryptedPrivateKey;

  public static Sm2EnvelopedKey getInstance(Object obj){
    if (obj instanceof Sm2EnvelopedKey){
      return (Sm2EnvelopedKey)obj;
    }if (obj instanceof byte[]){
      return new Sm2EnvelopedKey((byte[]) obj);
    }
    throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
  }

  public Sm2EnvelopedKey(byte[] data){
    ASN1Sequence sequence = ASN1Sequence.getInstance(data);
    this.symAlgId = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
    this.sm2Cipher = Sm2Cipher.getInstance(sequence.getObjectAt(1));
    this.sm2PublicKey = ASN1BitString.getInstance(sequence.getObjectAt(2));
    this.sm2EncryptedPrivateKey = ASN1BitString.getInstance(sequence.getObjectAt(3));
  }



  public Sm2EnvelopedKey(AlgorithmIdentifier symAlgId, Sm2Cipher sm2Cipher,
      ASN1BitString sm2PublicKey, ASN1BitString sm2EncryptedPrivateKey) {
    this.symAlgId = symAlgId;
    this.sm2Cipher=sm2Cipher;
    this.sm2PublicKey=sm2PublicKey;
    this.sm2EncryptedPrivateKey=sm2EncryptedPrivateKey;

  }


  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    vector.add(symAlgId);
    vector.add(sm2Cipher);
    vector.add(sm2PublicKey);
    vector.add(sm2EncryptedPrivateKey);
    return new DERSequence(vector);
  }
}
