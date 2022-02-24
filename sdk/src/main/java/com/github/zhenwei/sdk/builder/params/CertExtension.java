package com.github.zhenwei.sdk.builder.params;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author: zhangzhenwei
 * @description: CertExtension 证书使用扩展项
 * @since: 1.0.0
 * @date: 2022/2/21 10:28 下午
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class CertExtension {

    private String key;

    private byte[] value;

    /**
     * 编码方式
     */
    private CodingType codingType;

}
