http {
    #nginx原有配置
    #定义一个10MB的内存用于访问统计
    statistics_zone 10m; 
    #开启全局IP黑名单
    ip_blacklist on;
    #存储的IP数量
    ip_blacklist_size 10240;
    #IP在黑名单保留时间（秒）
    ip_blacklist_timeout 120;
    #名单保存在SEnginx内部
    ip_blacklist_mode local;
    #定义一个容量10MB的令牌空间，每个地址每秒只能请求10次（每秒补充10个令牌）
    limit_req_zone $binary_remote_addr zone=mudoom:10m rate=10r/s;
    #定义一个容量10MB的行为识别空间，最小有效请求数量是10个，采样周期是2秒
    ip_behavior_zone zone=brand:10m sample_base=10 sample_cycle=2s;

    #定义IP白名单
    geo $ip_wl {
        #使用以地址段的形式定义地址
        ranges;
        default 0;
        127.0.0.1-127.0.0.1 1;
    }
    #定义UA白名单，忽略常用网络爬虫
    whitelist_ua $ua_wl {
        #忽略大小写
        caseless;
        "Baiduspider" ".*\.baidu\.com";
        "Baidu-YunGuanCe-SLABot" ".*\.baidu\.com";
        "Googlebot" ".*\.google\.com";
        "360Spider" ".*\.360\.cn";
        "360JK" ".*\.360\.cn";
        "Sosospider" ".*\.soso\.com";
        "Sogou web spider" ".*\.sogou\.com";
        "bingbot" ".*\.bing\.com";
    }
    server{
        #原有server配置

        #定义一个虚拟server名，用于SEnginx访问统计显示
        virtual_server_name www.mudoom.com;
        #在当前server上开启ip识别空间brand并进行敏感url访问行为识别。
        ip_behavior zone=brand type=sensitive_url;

        #开启机器人挑战
        location @process {            #将全局IP白名单和User-Agent白名单作为机器人挑战白名单
            robot_mitigation_global_whitelist ua_var_name=ua_wl ip_var_name=ip_wl ip_var_value=1;
            #开启Robot Mitigation模块（机器人缓解）
            robot_mitigation on;
            #机器人挑战模式（JS）
            robot_mitigation_mode js;
            #黑名单失败次数上限
            robot_mitigation_blacklist 50;
            #挑战成功后的有效时间（秒）
            robot_mitigation_timeout 600;
            #关闭挑战ajax类型的请求
            robot_mitigation_challenge_ajax off;
            
            #php-fpm等原有配置
            fastcgi_pass 127.0.0.1:9000;
            ...
        }
        #请求可查看当前黑名单，安全起见需限定为内部访问
        location /blacklist_show {            allow 127.0.0.1;
            deny all;
            ip_blacklist_show;
        }

        #请求可清空黑名单列表，安全起见需限定为内部访问
        location /blacklist_flush {
            allow 127.0.0.1;
            deny all;
            ip_blacklist_flush;
        }        #请求可显示SEnginx访问统计，安全起见需限定为内部访问 
        location /stats {
            allow 127.0.0.1;
            deny all;
            statistics;
        }        #用于阻断的location
        location /RequestDenied {
	    return 403;
        }

        #使用安全模块控制的location配置
        location /mudoom {
            #敏感资源标识
            ip_behavior_sensitive;
            #原有令牌100枚，超出则触发机器人挑战
            limit_req zone=mudoom burst=100 forbid_action=@process condition=$cond;
            #当请求非敏感资源的占比小于30%时触发机器人挑战
            ifall ($insensitive_percent >= 0) ($insensitive_percent < 30) {
                set $cond 1;
            }

            #将全局IP白名单和User-Agent白名单作为cookie防篡改白名单 
            cookie_poisoning_whitelist ua_var_name=ua_wl ip_var_name=ip_wl ip_var_value=1;
            #cookie防篡改功能
            cookie_poisoning off;
            #指定发现cookie被篡改时执行的动作 block阻断、pass放行 、remove删除被篡改的cookie值 
            cookie_poisoning_action block;
            #阻断超过5次后加入黑名单
            cookie_poisoning_action blacklist,5;            #发现攻击时，是否向error log中写入log
            cookie_poisoning_log on;
 
            #将全局IP白名单和User-Agent白名单作为Naxsi白名单 
            naxsi_whitelist ua_var_name=ua_wl ip_var_name=ip_wl ip_var_value=1;
            #启动学习模块
	    LearningMode;
            #安全规则激活
            #SecRulesEnabled;
            #安全规则规避
	    #SecRulesDisabled;
	    #安全规则触发行为 
	    DeniedUrl "/RequestDenied";            #安全规则
	    CheckRule "$XSS >= 4" BLOCK;
	    CheckRule "$TRAVERSAL >= 4" BLOCK;
	    CheckRule "$EVADE >= 8" BLOCK;
	    CheckRule "$UPLOAD >= 8" BLOCK;
	    CheckRule "$RFI >= 8" BLOCK;
	    CheckRule "$SQL >= 8" BLOCK;

            #php-fpm等原有配置
            fastcgi_pass 127.0.0.1:9000;
            ...
        }
    }
}

