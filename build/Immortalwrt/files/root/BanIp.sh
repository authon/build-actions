#!/bin/sh
#
# dropBrute.sh by robzr (modified for nftables)
#
# minimalist OpenWRT/dropbear ssh brute force attack banning script
# using nftables instead of iptables
#

# How many bad attempts before banning (based on recent attempts)
allowedAttempts=10

# How long IPs are banned for (7 days in seconds)
secondsToBan=$((60*60*24*7))

# the "lease" file - stored in /etc to persist across reboots
leaseFile=/etc/dropBrute.leases

# This is the nftables chain that drop commands will go into.
nftChain=dropBrute

# nftables table and family
nftTable=inet filter
nftFamily=inet

# You can put default leasefile entries in the following space.
# Syntax is simply "leasetime _space_ IP_or_network".  A leasetime of -1 is a
# whitelist entry, and a leastime of 0 is a permanent blacklist entry.
[ -f $leaseFile ] || cat <<__EOF__>>$leaseFile
-1 10.10.10.1/24
__EOF__

# End of user customizable variables

nft='/usr/sbin/nft'

# Check if system date is set correctly
[ `date +'%s'` -lt 1609459200 ] && echo "System date not set correctly, aborting." && exit -1

# Initialize nftables configuration if needed
$nft list table $nftFamily $nftTable >/dev/null 2>&1 || {
  echo "Creating nftables table $nftTable"
  $nft add table $nftFamily $nftTable
}

# Create chain if it doesn't exist
$nft list chain $nftTable $nftChain >/dev/null 2>&1 || {
  echo "Creating nftables chain $nftChain"
  $nft add chain $nftTable $nftChain "{ type filter hook input priority 0; policy accept; }"
  # Add reference to our chain in the input path for SSH
  $nft add rule $nftTable input tcp dport 22 jump $nftChain
  # Add rate limiting for new connections
  $nft add rule $nftTable input tcp dport 22 ct state new limit rate 6/minute burst 6 packets accept
}

today=`date +'%b %d'`
now=`date +'%s'`
nowPlus=$((now + secondsToBan))

echo "Running dropBrute on `date` ($now)"

# Find new bad IPs - only check today's logs
for badIP in `logread | grep "$today" | awk -F 'from |:' '/dropbear.*attempt.*from/ {print $(NF-1)}' | sort -u`; do
  # Count attempts from this IP today
  found=`logread | grep "$today" | awk -F 'from |:' '/dropbear.*attempt.*from/ {print $(NF-1)}' | fgrep -c $badIP`
  
  if [ $found -gt $allowedAttempts ]; then
    # Check if IP is already in lease file
    if grep -q " $badIP$" $leaseFile; then
      # Update expiration time if it's a temporary ban
      currentLease=$(grep " $badIP$" $leaseFile | cut -f1 -d' ')
      if [ $currentLease -gt 0 ]; then
        sed -i "s/^.* $badIP$/$nowPlus $badIP/" $leaseFile
        echo "Updated ban expiration for $badIP until $(date -d @$nowPlus)"
      fi
    else
      # Add new temporary ban
      echo "$nowPlus $badIP" >> $leaseFile
      echo "Added new ban for $badIP until $(date -d @$nowPlus)"
    fi
  fi
done

# Process lease file and update nftables rules
while read -r leaseTime leaseIP; do
  # Skip empty lines
  [ -z "$leaseTime" ] || [ -z "$leaseIP" ] && continue
  
  # Check if rule for this IP already exists
  ruleExists=$($nft list ruleset | grep -c "$nftTable $nftChain .* $leaseIP")
  
  if [ $leaseTime -lt 0 ]; then
    # Whitelist rule (-1 = permanent whitelist)
    if [ $ruleExists -eq 0 ]; then
      echo "Adding whitelist rule for $leaseIP"
      $nft add rule $nftTable $nftChain ip saddr $leaseIP accept
    fi
  elif [ $leaseTime -eq 0 ]; then
    # Permanent blacklist (0 = permanent blacklist)
    if [ $ruleExists -eq 0 ]; then
      echo "Adding permanent blacklist rule for $leaseIP"
      $nft add rule $nftTable $nftChain ip saddr $leaseIP drop
    fi
  elif [ $now -gt $leaseTime ]; then
    # Expired temporary ban - remove it
    echo "Removing expired ban for $leaseIP"
    $nft delete rule $nftTable $nftChain ip saddr $leaseIP drop 2>/dev/null
    sed -i "/ $leaseIP$/d" $leaseFile
  else
    # Active temporary ban
    if [ $ruleExists -eq 0 ]; then
      echo "Adding temporary ban for $leaseIP until $(date -d @$leaseTime)"
      $nft add rule $nftTable $nftChain ip saddr $leaseIP drop
    fi
  fi
done < $leaseFile
