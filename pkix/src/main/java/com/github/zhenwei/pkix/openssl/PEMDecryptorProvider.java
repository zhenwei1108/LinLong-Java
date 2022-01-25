package com.github.zhenwei.pkix.openssl;

import com.github.zhenwei.pkix.operator.OperatorCreationException;

public interface PEMDecryptorProvider {

  PEMDecryptor get(String dekAlgName)
      throws OperatorCreationException;
}