#!/bin/sh
#
# dropBrute.sh - 修复nftables语法错误版本
#

# 配置参数
allowedAttempts=10
secondsToBan=$((60*60*24*7))
leaseFile=/etc/dropBrute.leases
nftChain=dropBrute
nftTable=fw4  # 已将filter修改为fw4
nftFamily=inet
baseChain=input

# 初始化封禁文件
[ -f "$leaseFile" ] || {
    cat <<__EOF__ > "$leaseFile"
-1 10.10.10.1/24
__EOF__
}

# 检查nft是否安装
nft='/usr/sbin/nft'
if [ ! -x "$nft" ]; then
    echo "错误：nft命令不存在，请安装nftables"
    exit 1
fi

# 检查系统时间
if [ $(date +'%s') -lt 1609459200 ]; then
    echo "错误：系统时间未正确设置"
    exit 1
fi

# 确保表存在
if ! $nft list table "$nftFamily" "$nftTable" >/dev/null 2>&1; then
    echo "创建表: $nftFamily $nftTable"
    $nft add table "$nftFamily" "$nftTable"
fi

# 确保基础链存在
if ! $nft list chain "$nftFamily" "$nftTable" "$baseChain" >/dev/null 2>&1; then
    echo "创建基础链: $nftFamily $nftTable $baseChain"
    $nft add chain "$nftFamily" "$nftTable" "$baseChain" "{"\
"type filter hook input priority 0;"\
"policy accept;"\
"}"
fi

# 确保自定义链存在
if ! $nft list chain "$nftFamily" "$nftTable" "$nftChain" >/dev/null 2>&1; then
    echo "创建自定义链: $nftFamily $nftTable $nftChain"
    $nft add chain "$nftFamily" "$nftTable" "$nftChain" "{"\
"type filter hook input priority 0;"\
"policy accept;"\
"}"
    
    # 添加SSH跳转规则（使用更兼容的语法）
    if ! $nft list ruleset | grep -q "jump $nftChain"; then
        echo "添加SSH跳转规则"
        $nft add rule "$nftFamily" "$nftTable" "$baseChain" tcp dport 22 jump "$nftChain"
    fi
    
    # 添加速率限制规则
    if ! $nft list ruleset | grep -q "limit rate 6/minute"; then
        echo "添加速率限制规则"
        $nft add rule "$nftFamily" "$nftTable" "$baseChain" tcp dport 22 ct state new limit rate 6/minute burst 6 packets accept
    fi
fi

today=$(date +'%b %d')
now=$(date +'%s')
nowPlus=$((now + secondsToBan))

echo "运行dropBrute于 $(date) ($now)"

# 提取恶意IP
for badIP in $(logread | grep "$today" | grep 'dropbear.*attempt.*from' | \
    sed -n 's/.*from \([0-9.]\+\):.*/\1/p' | sort -u); do
    
    found=$(logread | grep "$today" | grep 'dropbear.*attempt.*from' | \
        sed -n 's/.*from \([0-9.]\+\):.*/\1/p' | grep -c "^$badIP$")
    
    if [ "$found" -gt "$allowedAttempts" ]; then
        if grep -q " $badIP$" "$leaseFile"; then
            currentLease=$(grep " $badIP$" "$leaseFile" | cut -f1 -d' ')
            if [ "$currentLease" -gt 0 ]; then
                sed -i "s/^.* $badIP$/$nowPlus $badIP/" "$leaseFile"
                echo "更新$badIP的封禁时间至 $(date -d @$nowPlus)"
            fi
        else
            echo "$nowPlus $badIP" >> "$leaseFile"
            echo "添加$badIP的新封禁至 $(date -d @$nowPlus)"
        fi
    fi
done

# 处理封禁列表
while read -r leaseTime leaseIP; do
    [ -z "$leaseTime" ] || [ -z "$leaseIP" ] && continue
    
    ruleExists=$($nft list ruleset | grep -c "$nftFamily $nftTable $nftChain .* $leaseIP")
    
    if [ "$leaseTime" -lt 0 ]; then
        # 白名单
        if [ "$ruleExists" -eq 0 ]; then
            echo "添加白名单规则: $leaseIP"
            $nft add rule "$nftFamily" "$nftTable" "$nftChain" ip saddr "$leaseIP" accept
        fi
    elif [ "$leaseTime" -eq 0 ]; then
        # 永久黑名单
        if [ "$ruleExists" -eq 0 ]; then
            echo "添加永久黑名单规则: $leaseIP"
            $nft add rule "$nftFamily" "$nftTable" "$nftChain" ip saddr "$leaseIP" drop
        fi
    elif [ "$now" -gt "$leaseTime" ]; then
        # 移除过期封禁
        echo "移除过期封禁: $leaseIP"
        $nft delete rule "$nftFamily" "$nftTable" "$nftChain" ip saddr "$leaseIP" drop 2>/dev/null
        sed -i "/ $leaseIP$/d" "$leaseFile"
    else
        # 临时封禁
        if [ "$ruleExists" -eq 0 ]; then
            echo "添加临时封禁: $leaseIP 至 $(date -d @$leaseTime)"
            $nft add rule "$nftFamily" "$nftTable" "$nftChain" ip saddr "$leaseIP" drop
        fi
    fi
done < "$leaseFile"
