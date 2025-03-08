#!/bin/sh
. /usr/share/openclash/log.sh
. /lib/functions.sh

# This script is called by /etc/init.d/openclash
# Add your custom firewall rules here, they will be added after the end of the OpenClash iptables rules

LOG_OUT "Tip: Start Add Custom Firewall Rules..."

# 以下是广告过滤规则拉取脚本  
LOG_OUT "拉取 anti-AD 广告过滤规则…"  
curl -s https://anti-ad.net/anti-ad-for-dnsmasq.conf -o /tmp/dnsmasq.d/anti-ad-for-dnsmasq.conf  
# 广告过滤规则拉取脚本结束

# 以下是 GitHub520 加速规则拉取脚本  
# LOG_OUT "拉取 GitHub520 加速规则…"  
# sed -i '/# GitHub520 Host Start/,/# GitHub520 Host End/d' /etc/hosts  
# curl https://raw.hellogithub.com/hosts >> /etc/hosts  
# sed -i '/^$/d' /etc/hosts  
# sed -i '/!/d' /etc/hosts  
# GitHub520 加速规则拉取脚本结束

# 清理 DNS 缓存  
LOG_OUT "清理 DNS 缓存…"  
/etc/init.d/dnsmasq reload
