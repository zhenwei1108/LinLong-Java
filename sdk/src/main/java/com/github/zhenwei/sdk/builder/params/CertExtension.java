package com.github.zhenwei.sdk.builder.params;

import lombok.Data;

/**
 * @author: zhangzhenwei
 * @description: CertExtension 证书使用扩展项
 * @since: 1.0.0
 * @date: 2022/2/21 10:28 下午
 */
@Data
public class CertExtension {

    private String key;

    private byte[] value;

    /**
     * 编码方式
     */
    private CodingType codingType;

}
