package com.github.zhenwei.sdk.util;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

/**
 * @description: DateUtil
 *  时间工具
 * @author: zhangzhenwei
 * @since: 1.0.0
 * @date: 2022/3/10  10:40 下午
 */
public class DateUtil {

    /**
     * @param []
     * @return java.util.Date
     * @author zhangzhenwei
     * @description 当前时间
     * @date 2022/3/10  10:40 下午
     * @since:
     */
    public static Date now(){
        LocalDateTime now = LocalDateTime.now();
        return parse(now);
    }


    /**
     * @param [days]
     * @return java.util.Date
     * @author zhangzhenwei
     * @description 当前时间 + 指定天数
     * @date 2022/3/10  10:40 下午
     * @since:
     */
    public static Date nowPlusDays(int days){
        LocalDateTime result = LocalDateTime.now().plusDays(days);
        return parse(result);
    }


    public static Date parse(LocalDateTime localDateTime){
        return Date.from(localDateTime.toInstant(ZoneOffset.UTC));
    }


}
