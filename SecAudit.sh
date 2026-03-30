#!/bin/bash

tgt_services=("ssh" "apache2" "cron")
av_services=()

#Check for used services on the host
check_services() {
  local service
  for service in "${tgt_services[@]}"; do
    if systemctl is-active -q $service; then
      av_services+=("$service")
    else
      echo -e "================================================="
      echo -e " $service is not used, it will not be verified"
      echo -e "=================================================\n"
    fi
  done
}

#Check for ssh vulnerabilites
check_ssh() {
  local regle
  local vuln
  local desc
  ssh_vuln=("^PermitRootLogin yes|High Vulnerability : root connection authorized due to 'PermitRootLogin'"
            "^PermitEmptyPasswords yes|High Vulnerability : no password connection enabled due to 'PermitEmptyPasswords'"
            "^PasswordAuthentication yes|High Vulnerability : password connection enabled due to 'PasswordAuthentication'"
            "^ClientAliveInterval 0|High Vulnerability : no inactive ssh session timeout due to 'ClientAliveInterval'"
)
  echo -e "=================================="
  echo -e " Analyzing the SSH configuration..."
  echo -e "==================================\n"
  for regle in "${ssh_vuln[@]}"; do
    IFS='|' read -r vuln desc <<< "$regle"
    if grep -q -i "$vuln" "/etc/ssh/sshd_config"; then
    echo -e "$desc in sshd_config\n" >> ssh_vuln.txt
    fi
  done
} 

#Check for apache2 vulnerabilites
check_apache2() {
  local regle
  local vuln
  local desc
  apache2_vuln=("^Options Indexes|High Vulnerability : Directory Listing available due to 'Options Indexes'"
                "^ServerSignature On|High Vulnerability : Server version footprinting enabled due to 'ServerSignature'"
                "^ServerTokens OS|High Vulnerability : Server version footprinting enabled due to 'ServerTokens'"
                "^TraceEnable On|High Vulnerability : Cross-Site Tracing possible due to 'TraceEnable'"
 )
 echo -e "====================================="
 echo -e " Analyzing the apache2 configuration..."
 echo -e "=====================================\n"
 for regle in "${apache2_vuln[@]}"; do
   IFS='|' read -r vuln desc <<< "$regle"
   if grep -q -i "$vuln" "/etc/apache2/apache2.conf"; then
     echo -e "$desc in /etc/apache2/apache2.conf\n" >> apache2_vuln.txt
   fi
 done
}

#Check for cron vulnerabilites
check_cron() {
  check_rights=("/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly")
  echo -e "====================================="
  echo -e " Analyzing the cron configuration..."
  echo -e "=====================================\n"
  if [ ! -e "/etc/cron.allow" ]; then
    echo -e "High Vulnerability : cron.allow not created\n" >> cron_vuln.txt
  fi
  if [ $(stat -c "%a" /etc/crontab) -ne 600 ]; then
    echo -e "High Vulnerability : Permissive xwr rights for /etc/crontab\n" >> cron_vuln.txt
  fi
  for file in "${check_rights[@]}"; do
    if [ $(stat -c "%a" "$file") -ne 700 ] || [ $(stat -c "%U" "$file") != "root" ]; then
      echo -e "High Vulnerability : Permissive rights for $file\n" >> cron_vuln.txt
    fi
  done
}

#Execute the check for every used services on the host
check_av_services() {
  rm -f *_vuln.txt
  local service
  for service in "${av_services[@]}"; do
    case $service in
    "ssh") check_ssh ;;
    "apache2") check_apache2 ;;
    "cron") check_cron ;;
    *)
      break
      ;;
    esac
  done
}

#Generate a report in the terminal
generate_report() {
  local ligne
  local service
  for service in "${av_services[@]}"; do
    local compteur=1
    if [ -e "$service"_vuln.txt ]; then
      echo -e "============= $service Vulnerabilites ============="
      while read ligne; do
        echo -e "Ligne $compteur : $ligne"
        compteur=$((compteur + 1))
      done < "$service"_vuln.txt
      echo -e "=================================================\n"
    fi
  done
}

check_root() {
  if [ "$EUID" -ne 0 ]; then
    echo "Please run as root !"
    exit 1
  fi
}

# Main 
  check_root
  echo -e "\n"
  echo -e "Checking for used services...\n"
  sleep 1
  check_services
  sleep 1
  echo -e "Checking for services configurations...\n"
  sleep 1
  check_av_services
  sleep 1
  echo -e "Generating the report...\n"
  generate_report
  sleep 1
