package org.sdk.crypto.key.asymmetric;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import org.sdk.crypto.init.InitProvider;

public class SignVerify extends InitProvider {

  /*
  定义G为SM2曲线的基点，n为G的阶，用户私钥d，待签名的摘要信息为e
产生随机数k∈[1,n-1]
计算椭圆曲线点Q = [k]G=(x1, y1)
计算r = (e+x1) mod n，若r = 0或r+k = n，重新产生随机数
计算s = ((1+d)-1(k-rd)) mod n，若s = 0，重新产生随机数
(r,s)即数字签名结果

   */
  public static byte[] sm2SignData(PrivateKey privateKey, byte[] sourceData)
      throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
    Signature signature = Signature.getInstance("SM3WithSM2", BC_PROVIDER);
    signature.initSign(privateKey);
    signature.update(sourceData);
    return signature.sign();
  }

  public static boolean sm2VerifyData(PublicKey publicKey, byte[] sourceData, byte[] signedData)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
    Signature signature = Signature.getInstance("SM3WithSM2", BC_PROVIDER);
    signature.initVerify(publicKey);
    signature.update(sourceData);
    return signature.verify(signedData);
  }



  public static void main(String[] args)
      throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
    KeyPair keyPair = AsymmetryKey.genKeyPair(AsymmetryKeyEnums.SM2_256);
    byte[] bytes = sm2SignData(keyPair.getPrivate(), "adsf".getBytes(StandardCharsets.UTF_8));
  }

}
