package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.enums.CipherAlgEnum;
import com.github.zhenwei.core.enums.exception.CipherExceptionMessageEnum;
import com.github.zhenwei.core.exception.WeGooCipherException;
import com.github.zhenwei.sdk.init.ProviderEngine;
import com.github.zhenwei.sdk.util.ArrayUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * @description: 加解密实现
 * @author: zhangzhenwei
 * @date: 2022/2/16 22:41
 * @since 1.0.0
 */
public class CipherBuilder {

    public static byte[] cipher(CipherAlgEnum cipherAlgEnum, Key key, byte[] sourceData, byte[] iv, boolean encrypt)
            throws WeGooCipherException {
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgEnum.getAlg(), ProviderEngine.getProvider());

            //判断是否需要初始化向量
            if (cipherAlgEnum.getModeEnum().isNeedIV()) {
                if (ArrayUtils.isEmpty(iv)) {
                    throw new WeGooCipherException(CipherExceptionMessageEnum.iv_param_empty_err);
                }
                cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            } else {
                cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);
            }
            return cipher.doFinal(sourceData);
        } catch (WeGooCipherException e) {
            throw e;
        } catch (Exception e) {
            throw new WeGooCipherException(CipherExceptionMessageEnum.cipher_data_err, e);
        }
    }

}