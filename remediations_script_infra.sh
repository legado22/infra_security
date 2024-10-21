#!/bin/bash

# Colors for compliant and non-compliant messages
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Initialize variables
compliance_count=0
non_compliance_count=0


# 1. Check system-wide crypto policy
echo "Checking system-wide crypto policy..."
current_policy=$(update-crypto-policies --show)

if [[ "$current_policy" == "FUTURE" || "$current_policy" == "FIPS" ]]; then
  echo -e "${GREEN}Crypto policy is already set to $current_policy. Compliant Line 3.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED} Line 3 Crypto policy is not set to FUTURE or FIPS. Current policy is $current_policy. Non-Compliant Line 3.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
  
  echo -e "${RED} Line 3: Automatically remediating by setting the crypto policy to FUTURE...${NC}"
  
  # Automatically apply the remediation by setting the policy to FUTURE
  update-crypto-policies --set FUTURE

  # Verify if the remediation was successful
  new_policy=$(update-crypto-policies --show)
  if [[ "$new_policy" == "FUTURE" ]]; then
    echo -e "${GREEN}Remediation successful. Crypto policy is now set to FUTURE.${NC}"
    compliance_count=$((compliance_count + 1))  # Mark as compliant after remediation
  else
    echo -e "${RED}Remediation failed. Crypto policy is still set to $new_policy.${NC}"
  fi
fi


echo " Level 5"

# Check if /var has a separate partition
echo "Excel sheet cell 4"
echo "Checking if separate partition exists for /var..."

if mount | grep -E '\s/var\s' > /dev/null; then
  # Separate partition exists - compliance
  echo -e "${GREEN}/var has a separate partition. Compliant Line 5.${NC}"
  compliance_count=$((compliance_count + 1))
else
  # Separate partition does not exist - non-compliance
  echo -e "${RED}/var does NOT have a separate partition. Non-Compliant Line 5.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
fi


echo " Level 6"

# Check if /var/tmp has a separate partition
echo "Excel sheet cell 6"
echo "Checking if separate partition exists for /var/tmp..."

if mount | grep "/var/tmp" > /dev/null; then
  # Separate partition exists - compliance
  echo -e "${GREEN}/var/tmp has a separate partition. Compliant Line 6.${NC}"
  compliance_count=$((compliance_count + 1))
else
  # Separate partition does not exist - non-compliance
  echo -e "${RED}/var/tmp does NOT have a separate partition. Non-Compliant Line 6.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
fi

echo " Level 7"

# Check if /var/log has a separate partition
echo "Excel sheet cell 7"
echo "Checking if separate partition exists for /var/log..."

if mount | grep "/var/log" > /dev/null; then
  # Separate partition exists - compliance
  echo -e "${GREEN}/var/log has a separate partition. Compliant Line 7.${NC}"
  compliance_count=$((compliance_count + 1))
else
  # Separate partition does not exist - non-compliance
  echo -e "${RED}/var/log does NOT have a separate partition. Non-Compliant Line 7.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
fi

echo " Level 8"

# Check if /var/log/audit has a separate partition
echo "Excel sheet cell 8"
echo "Checking if separate partition exists for /var/log/audit..."

if mount | grep "/var/log/audit" > /dev/null; then
  # Separate partition exists - compliance
  echo -e "${GREEN}/var/log/audit has a separate partition. Compliant Line 8.${NC}"
  compliance_count=$((compliance_count + 1))
else
  # Separate partition does not exist - non-compliance
  echo -e "${RED}/var/log/audit does NOT have a separate partition. Non-Compliant Line 8.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
fi

echo " Level 9"

# Check if /home has a separate partition
echo "Excel sheet cell 9"
echo "Checking if separate partition exists for /home..."

if mount | grep "/home" > /dev/null; then
  # Separate partition exists - compliance
  echo -e "${GREEN}/home has a separate partition. Compliant Line 9.${NC}"
  compliance_count=$((compliance_count + 1))
else
  # Separate partition does not exist - non-compliance
  echo -e "${RED}/home does NOT have a separate partition. Non-Compliant Line 9.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
fi



# 3. Check unused filesystems
echo "Excel sheet cell 10"
echo "Checking unused filesystems..."

for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat; do
  if lsmod | grep "$fs" &> /dev/null; then
    # Filesystem is loaded - non-compliant
    echo -e "${RED}$fs is currently loaded. Non-Compliant Line 10.${NC}"
    non_compliance_count=$((non_compliance_count + 1))

    # Automatically apply the remediation to disable the filesystem
    echo -e "${RED}Applying remediation: Disabling $fs to prevent it from loading in the future.${NC}"
    echo "install $fs /bin/true" >> /etc/modprobe.d/disable-$fs.conf

    # Verify if the remediation was successfully applied
    if grep "install $fs /bin/true" /etc/modprobe.d/disable-$fs.conf &> /dev/null; then
      echo -e "${GREEN}$fs is now disabled. Remediation applied successfully.${NC}"
    else
      echo -e "${RED}Failed to apply remediation for $fs. Please check manually.${NC}"
    fi
  else
    # Filesystem is not loaded - compliant
    echo -e "${GREEN}$fs is not loaded. Compliant Line 10.${NC}"
    compliance_count=$((compliance_count + 1))
  fi
done


echo "Level 11"

# 4. Check if mounting of vFAT filesystems is limited
echo "Excel sheet cell 11"
echo "Checking vFAT mounting limitation..."

if grep -q "install vfat /bin/true" /etc/modprobe.d/disable-vfat.conf; then
  # vFAT mounting is limited - compliant
  echo -e "${GREEN}vFAT mounting is limited. Compliant Line 11.${NC}"
  compliance_count=$((compliance_count + 1))
else
  # vFAT mounting is not limited - non-compliant
  echo -e "${RED}vFAT mounting is not limited. Non-Compliant Line 11.${NC}"
  non_compliance_count=$((non_compliance_count + 1))

  # Provide remediation command
  echo -e "${RED}The following command will remediate the issue: 'echo \"install vfat /bin/true\" >> /etc/modprobe.d/disable-vfat.conf' to limit vFAT mounting.${NC}"

  # Uncomment the remediation command to apply it
  echo "install vfat /bin/true" >> /etc/modprobe.d/disable-vfat.conf
  echo -e "${GREEN}vFAT mounting is now limited. Remediation applied.${NC}"
fi
 
# 2. Check if UEFI is used and if vFAT is appropriate
echo "Checking if UEFI requires vFAT..."
if grep -E -i '\svfat\s' /etc/fstab; then
  echo "vFAT is found in /etc/fstab. Reviewing if this is due to UEFI."
  echo "Please ensure vFAT is used only where appropriate, e.g., UEFI boot partition."
else
  echo "vFAT is not found in /etc/fstab for UEFI."
fi
 
# 3. Check if vFAT module is loaded if UEFI is not used
echo "If UEFI is not used, checking if vFAT module is correctly disabled..."
modprobe_output=$(modprobe -n -v vfat)
if [[ "$modprobe_output" == "install /bin/true" ]]; then
  echo -e "${GREEN}vFAT module is disabled. Compliant Line 11.${NC}"
else
  echo -e "${RED}vFAT module is not disabled. Non-Compliant Line 11.${NC}"
  # Remediation: Disable the vFAT module
  echo "Disabling vFAT module..."
  echo "install vfat /bin/true" >> /etc/modprobe.d/disable-vfat.conf
  echo -e "${GREEN}vFAT module has been disabled. Remediation applied.${NC}"
fi
 
# 4. Check if vFAT module is loaded
echo "Checking if vFAT module is loaded..."
if lsmod | grep -q vfat; then
  echo -e "${RED}vFAT module is currently loaded. Non-Compliant Line 11.${NC}"
 
  # Remediation: Unload the vFAT module if it is loaded
  echo "Unloading the vFAT module..."
  rmmod vfat
  echo -e "${GREEN}vFAT module has been unloaded. Remediation applied.${NC}"
else
  echo -e "${GREEN}vFAT module is not loaded. Compliant Line 11.${NC}"
fi

echo "Level 12"

# 5. Check and remediate software updates configuration
echo "Excel sheet cell 12"
echo "Checking if dnf-automatic is installed and enabled..."

# Check if dnf-automatic is installed
if ! rpm -q dnf-automatic &> /dev/null; then
  # If dnf-automatic is not installed, print non-compliance
  echo -e "${RED}dnf-automatic is not installed. Non-Compliant Line 12.${NC}"
  non_compliance_count=$((non_compliance_count + 1))

  # Automatically remediate: Install dnf-automatic
  echo -e "${RED}Remediating: Installing dnf-automatic...${NC}"
  sudo dnf install -y dnf-automatic
  if rpm -q dnf-automatic &> /dev/null; then
    echo -e "${GREEN}dnf-automatic has been successfully installed. Remediation applied.${NC}"
    compliance_count=$((compliance_count + 1))
  else
    echo -e "${RED}Failed to install dnf-automatic. Please check manually.${NC}"
  fi
else
  # If dnf-automatic is installed, print compliance
  echo -e "${GREEN}dnf-automatic is already installed. Compliant Line 12.${NC}"
  compliance_count=$((compliance_count + 1))
fi

# Check if dnf-automatic.timer is enabled
if systemctl is-enabled --quiet dnf-automatic.timer; then
  # If the timer is enabled, print compliance
  echo -e "${GREEN}dnf-automatic.timer is already enabled. Compliant Line 12.${NC}"
  compliance_count=$((compliance_count + 1))
else
  # If the timer is not enabled, print non-compliance and automatically enable it
  echo -e "${RED}dnf-automatic.timer is not enabled. Non-Compliant Line 12.${NC}"
  non_compliance_count=$((non_compliance_count + 1))

  # Automatically remediate: Enable the timer
  echo -e "${RED}Remediating: Enabling dnf-automatic.timer...${NC}"
  sudo systemctl enable --now dnf-automatic.timer
  if systemctl is-enabled --quiet dnf-automatic.timer; then
    echo -e "${GREEN}dnf-automatic.timer has been successfully enabled. Remediation applied.${NC}"
    compliance_count=$((compliance_count + 1))
  else
    echo -e "${RED}Failed to enable dnf-automatic.timer. Please check manually.${NC}"
  fi
fi


# echo "Level 13"

# # 6. Check sudo configuration
# echo "Excel sheet cell 13"
# echo "Checking sudo permissions... If not installed, manual intervention is needed."

# # Check if sudo is installed
# if ! rpm -q sudo &> /dev/null; then
#   echo -e "${RED}sudo is not installed. Manual intervention is required.${NC}"
#   non_compliance_count=$((non_compliance_count + 1))
# else
#   echo -e "${GREEN}sudo is installed.${NC}"

#   # Check sudo permissions in /etc/sudoers
#   if grep -q "admin ALL=(ALL) ALL" /etc/sudoers; then
#     echo -e "${GREEN}Sudo permissions for admin are already configured. Compliant Line 13.${NC}"
#     compliance_count=$((compliance_count + 1))
#   else
#     echo -e "${RED}Sudo permissions for admin are not configured. Non-Compliant Line 13.${NC}"
#     non_compliance_count=$((non_compliance_count + 1))

#     # Suggest manual remediation (since modifying sudoers can be dangerous automatically)
#     echo -e "${RED}Manual remediation: Add the following line to /etc/sudoers to grant admin sudo privileges:${NC}"
#     echo "admin ALL=(ALL) ALL"
#     echo "Use the command 'sudo visudo' to safely edit the file."
#   fi
# fi


echo "Starting filesystem security check Line 14"

# 1. Check world-writable files
echo "Checking world-writable files..."
find / -perm /o=w -type f 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${RED}Found world-writable files. Non-Compliant Line 14 .${NC}"
    non_compliance_count=$((non_compliance_count + 1))
    echo "Removing world-writable permissions..."
    find / -perm /o=w -type f -exec chmod o-w {} \;
else
    echo -e "${GREEN}No world-writable files found. Compliant Line 14 .${NC}"
    compliance_count=$((compliance_count + 1))
fi

# 2. Check unauthorized SUID/SGID files
echo "Checking for unauthorized SUID/SGID files..."
find / -perm /6000 -type f 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${RED}Found unauthorized SUID/SGID files. Non-Compliant Line 14 .${NC}"
    non_compliance_count=$((non_compliance_count + 1))
    echo "Removing SUID/SGID permissions..."
    find / -perm /6000 -type f -exec chmod a-s {} \;
else
    echo -e "${GREEN}No unauthorized SUID/SGID files found. Compliant Line 14 .${NC}"
    compliance_count=$((compliance_count + 1))
fi

# 3. Check for empty password fields
echo "Checking for empty password fields..."
awk -F: '($2 == "") {print $1}' /etc/shadow
 
if [ $? -eq 0 ]; then
    echo -e "${RED}Found accounts with empty passwords. Non-Compliant Line 14 .${NC}"
    non_compliance_count=$((non_compliance_count + 1))
    echo "Locking accounts with empty passwords..."
 
    for user in $(awk -F: '($2 == "") {print $1}' /etc/shadow); do
        # Lock the accounts with empty passwords
        echo "Locking account: $user"
        passwd -l "$user"
    done
 
    # Remediation step: Force password change at next login for these accounts
    for user in $(awk -F: '($2 == "") {print $1}' /etc/shadow); do
        echo "Forcing password change for user: $user"
        chage -d 0 "$user"
    done
else
    echo -e "${GREEN}No accounts with empty passwords found. Compliant Line 14 .${NC}"
    compliance_count=$((compliance_count + 1))
fi

# 4. Check filesystem integrity with AIDE
echo "Checking AIDE installation for filesystem integrity..."
if rpm -q aide &> /dev/null; then
    echo -e "${GREEN}AIDE is installed. Compliant Line 14 .${NC}"
    compliance_count=$((compliance_count + 1))
    sudo aide --check
else
    echo -e "${RED}AIDE is not installed. Non-Compliant Line 14 .${NC}"
    non_compliance_count=$((non_compliance_count + 1))
    echo "Installing AIDE..."
    sudo yum install -y aide
    sudo aide --init
    sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
fi

# # 7. Check if LUKS encryption is enabled
# echo "Checking if LUKS encryption is enabled for sensitive partitions..."
# if cryptsetup status $(lsblk | grep luks | awk '{print $1}') &> /dev/null; then
#     echo -e "${GREEN}LUKS encryption is enabled. Compliant.${NC}"
#     compliance_count=$((compliance_count + 1))
# else
#     echo -e "${RED}LUKS encryption is not enabled. Non-Compliant Line 14.${NC}"
#     non_compliance_count=$((non_compliance_count + 1))
#     # Remediation suggestion: Set up LUKS encryption on the target partition
#     echo "Remediating: Setting up LUKS encryption for the partition..."
#     partition_to_encrypt=$(lsblk | grep -v luks | awk '{print $1}' | head -n 1)  # Specify your target partition
 
#     echo "Encrypting partition: $partition_to_encrypt"
#     # Uncomment to encrypt the partition with LUKS (we should check carefully before running this onnproduction env)
#     # cryptsetup luksFormat /dev/$partition_to_encrypt
#     # After setting up encryption, open the partition
#     echo "Opening LUKS encrypted partition..."
#     # Uncomment to open the partition
#     # cryptsetup open /dev/$partition_to_encrypt encrypted_partition_name
#     echo "LUKS encryption setup completed. Please configure fstab for persistence."
 
#     echo -e "${GREEN}Remediation applied: LUKS encryption configured.${NC}"
# fi

# 8. Check for noexec, nosuid, and nodev mount options
echo "Checking mount options..."
for partition in /tmp /var/tmp /dev/shm; do
    if mount | grep "$partition" | grep -q "noexec,nosuid,nodev"; then
        echo -e "${GREEN}$partition has secure mount options. Compliant Line 14.${NC}"
        compliance_count=$((compliance_count + 1))
    else
        echo -e "${RED}$partition does not have secure mount options. Non-Compliant Line 14.${NC}"
        non_compliance_count=$((non_compliance_count + 1))
        echo "Add secure mount options in /etc/fstab and remount the filesystem."
    fi
done



# echo "Level 15"

# # Check if GRUB has a password set
# echo "Checking if GRUB is password protected..."

# if grep -q "password_pbkdf2" /etc/grub.d/40_custom; then
#   echo -e "${GREEN}GRUB is password protected. Boot settings are secured Line 15.${NC}"
#   compliance_count=$((compliance_count + 1))
# else
#   echo -e "${RED}GRUB is not password protected. Boot settings are not secured Line 15.${NC}"
#   non_compliance_count=$((non_compliance_count + 1))  

#   # Automatic remediation: Secure GRUB with password
#   echo -e "${RED}Securing GRUB with a password...${NC}"
#   PASSWORD_HASH=$(echo "server_password_here" | grub-mkpasswd-pbkdf2 | grep 'grub.pbkdf2' | awk '{print $NF}')
  
#   sudo bash -c "cat <<EOF >> /etc/grub.d/40_custom
# set superusers=\"root\"
# password_pbkdf2 root $PASSWORD_HASH
# EOF"
  
#   sudo update-grub
#   echo -e "${GREEN}GRUB has been secured with a password. Remediation applied.${NC}"
# fi

# # 16. Check if boot parameters modification is disabled
# echo "Checking if boot parameter modifications are restricted Line 16"

# if grep -q 'quiet splash' /etc/default/grub; then
#   echo -e "${GREEN}Boot parameter modifications are restricted. Boot settings are secured Line 16.${NC}"
#   compliance_count=$((compliance_count + 1))
# else
#   echo -e "${RED}Boot parameter modifications are not restricted. Boot settings are not secured Line 16.${NC}"
#   non_compliance_count=$((non_compliance_count + 1))

#   # Automatic remediation: Restrict boot parameter modifications
#   echo -e "${RED}Restricting boot parameter modifications...${NC}"
#   sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*/& quiet splash/' /etc/default/grub
#   sudo update-grub
#   echo -e "${GREEN}Boot parameter modifications have been restricted. Remediation applied.${NC}"
# fi


echo "Level 19"
echo "Checking SELinux configuration..."

# Function to check if SELinux is installed
check_selinux_installed() {
  if rpm -q selinux-policy &> /dev/null; then
    echo -e "${GREEN}SELinux is installed. Compliant Line 19.${NC}"
    compliance_count=$((compliance_count + 1))
  else
    echo -e "${RED}SELinux is not installed. Non-Compliant Line 19.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
    
    # Automatic remediation to install SELinux
    echo -e "${RED}Remediating: Installing SELinux...${NC}"
    sudo yum install -y selinux-policy selinux-policy-targeted

    # Verify if the installation was successful
    if rpm -q selinux-policy &> /dev/null; then
      echo -e "${GREEN}SELinux has been successfully installed. Remediation applied.${NC}"
      compliance_count=$((compliance_count + 1))
    else
      echo -e "${RED}Failed to install SELinux. Please check manually.${NC}"
    fi
  fi
}


echo "Level 20"

# Function to check if SELinux is enabled in the bootloader
check_selinux_bootloader() {
  if grep -q 'selinux=0' /proc/cmdline; then
    echo -e "${RED}SELinux is disabled in bootloader. Non-Compliant Line 20.${NC}"
    non_compliance_count=$((non_compliance_count + 1))

    # Automatic remediation: Remove 'selinux=0' from bootloader configuration
    echo -e "${RED}Remediating: Enabling SELinux in bootloader...${NC}"
    sudo sed -i "s/selinux=0//g" /etc/default/grub
    sudo grub2-mkconfig -o /boot/grub2/grub.cfg

    # Verify if the remediation was successful
    if ! grep -q 'selinux=0' /proc/cmdline; then
      echo -e "${GREEN}SELinux has been enabled in the bootloader. Remediation applied.${NC}"
      compliance_count=$((compliance_count + 1))
    else
      echo -e "${RED}Failed to enable SELinux in the bootloader. Please check manually.${NC}"
    fi
  else
    echo -e "${GREEN}SELinux is enabled in bootloader. Compliant Line 20.${NC}"
    compliance_count=$((compliance_count + 1))
  fi
}


echo "Level 21"

# Function to check if SELinux policy is loaded
check_selinux_policy() {
  if sestatus | grep -q "Loaded policy name:"; then
    echo -e "${GREEN}SELinux policy is loaded. Compliant Line 21.${NC}"
    compliance_count=$((compliance_count + 1))
  else
    echo -e "${RED}SELinux policy is not loaded. Non-Compliant Line 21.${NC}"
    non_compliance_count=$((non_compliance_count + 1))

    # Automatic remediation to load SELinux policy
    echo -e "${RED}Remediating: Loading SELinux policy...${NC}"
    sudo load_policy

    # Verify if the remediation was successful
    if sestatus | grep -q "Loaded policy name:"; then
      echo -e "${GREEN}SELinux policy has been successfully loaded. Remediation applied.${NC}"
      compliance_count=$((compliance_count + 1))
    else
      echo -e "${RED}Failed to load SELinux policy. Please check manually.${NC}"
    fi
  fi
}

echo "Level 22"
# Check if SELinux is enforcing
if [[ $(getenforce) == "Enforcing" ]]; then
    echo -e "${GREEN}SELinux is enforcing. Line 22 is Compliant.${NC}"
else
    echo -e "${RED}SELinux is not enforcing.Line 22 is Non-Compliant.${NC}"
 
    # Suggest remediation
    echo "Run the following command to enforce SELinux immediately: 'sudo setenforce 1'"
    echo "To make this change persistent across reboots, run the following command:"
    echo "'sudo sed -i \"s/^SELINUX=.*/SELINUX=enforcing/\" /etc/selinux/config'"
 
    # Automatic remediation: Set SELinux to enforcing mode
    echo -e "${RED}Remediating: Setting SELinux to enforcing mode...${NC}"
    sudo setenforce 1
 
    # Update /etc/selinux/config to enforce persistence across reboots
    echo -e "${RED}Updating SELinux configuration to ensure persistence across reboots...${NC}"
    sudo sed -i "s/^SELINUX=.*/SELINUX=enforcing/" /etc/selinux/config
 
    # Verify if the remediation was successful
    if sestatus | grep -q "Current mode: enforcing"; then
        echo -e "${GREEN}SELinux is now in enforcing mode. Remediation applied.${NC}"
        compliance_count=$((compliance_count + 1))
    else
        echo -e "${RED}Failed to set SELinux to enforcing mode. Please check manually.${NC}"
    fi
fi


echo "Level 23"

# Ensure no unconfined services exist
echo "Checking for unconfined services..."
unconfined_services=$(ps -eZ | grep unconfined_service_t)

if [ -z "$unconfined_services" ]; then
    echo -e "${GREEN}No unconfined services found. Compliant Line 23.${NC}"
    compliance_count=$((compliance_count + 1))
else
    echo -e "${RED}Unconfined services detected. Non-Compliant Line 23.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
    # Display the unconfined services
    echo -e "${RED}List of unconfined services:${NC}"
    echo -e "${RED}$unconfined_services${NC}"

    # Extract the process IDs of unconfined services
    unconfined_pids=$(ps -eZ | grep unconfined_service_t | awk '{print $2}')
    for pid in $unconfined_pids; do
        service_name=$(ps -p $pid -o comm=)
        echo -e "${RED}Stopping and killing $service_name (PID: $pid)...${NC}"
        # Attempt to kill the process
        sudo kill -9 $pid
        # Check if the process was killed successfully
        if ps -p $pid > /dev/null; then
            echo -e "${RED}Failed to kill $service_name (PID: $pid). Manual intervention may be required.${NC}"
            non_compliance_count=$((non_compliance_count + 1))
        else
            echo -e "${GREEN}$service_name (PID: $pid) has been successfully killed.${NC}"
            compliance_count=$((compliance_count + 1))
        fi
    done

    # Handle defunct processes (zombies)
    defunct_pids=$(ps -eZ | grep unconfined_service_t | grep '<defunct>' | awk '{print $2}')
    for defunct_pid in $defunct_pids; do
        parent_pid=$(ps -o ppid= -p $defunct_pid)
        echo -e "${RED}Killing parent process (PID: $parent_pid) of defunct service...${NC}"
        sudo kill -9 $parent_pid
        # Check if the parent process was killed successfully
        if ps -p $parent_pid > /dev/null; then
            echo -e "${RED}Failed to kill parent process (PID: $parent_pid). Manual intervention may be required.${NC}"
            non_compliance_count=$((non_compliance_count + 1))
        else
            echo -e "${GREEN}Parent process (PID: $parent_pid) of defunct service has been successfully killed.${NC}"
            compliance_count=$((compliance_count + 1))
        fi
    done

    # Verify if unconfined services still exist
    unconfined_services_post=$(ps -eZ | grep unconfined_service_t)
    if [ -z "$unconfined_services_post" ]; then
        echo -e "${GREEN}All unconfined services have been killed. Remediation applied.${NC}"
        compliance_count=$((compliance_count + 1))
    else
        echo -e "${RED}Some unconfined services still exist. Further manual intervention needed.${NC}"
        echo "$unconfined_services_post"
        non_compliance_count=$((non_compliance_count + 1))
    fi
fi



echo "Level 24"

# Ensure SETroubleshoot is not installed
echo "Checking if SETroubleshoot is installed..."
if rpm -q setroubleshoot &>/dev/null; then
  echo -e "${RED}SETroubleshoot is installed. Non-Compliant Line 24.${NC}"
  non_compliance_count=$((non_compliance_count + 1))

  # Optionally remove SETroubleshoot
  # Uncomment the following block if you want to automatically remove SETroubleshoot
echo -e "${RED}Removing SETroubleshoot...${NC}"
  yum remove -y setroubleshoot
   if [ $? -eq 0 ]; then
     echo -e "${GREEN}SETroubleshoot removed successfully. Remediation applied.${NC}"
     compliance_count=$((compliance_count + 1))
   else
     echo -e "${RED}Failed to remove SETroubleshoot. Please check manually.${NC}"
   fi

else
  echo -e "${GREEN}SETroubleshoot is not installed. Compliant Line 24.${NC}"
  compliance_count=$((compliance_count + 1))
fi



echo "Level 25"

# Ensure the MCS Translation Service (mcstrans) is not installed
echo "Checking if mcstrans is installed..."
if rpm -q mcstrans &>/dev/null; then
    echo -e "${RED}mcstrans is installed. Non-Compliant Line 25.${NC}"
    non_compliance_count=$((non_compliance_count + 1))

    # Automatic removal of mcstrans
    echo -e "${RED}Removing mcstrans...${NC}"
    yum remove -y mcstrans
    if [ $? -eq 0 ]; then
      echo -e "${GREEN}mcstrans removed successfully. Remediation applied.${NC}"
      compliance_count=$((compliance_count + 1))
    else
      echo -e "${RED}Failed to remove mcstrans. Please check manually.${NC}"
    fi

else
    echo -e "${GREEN}mcstrans is not installed. Compliant Line 25.${NC}"
    compliance_count=$((compliance_count + 1))
fi


echo "Checking warning banners... Excel sheet line 27"

# Define the warning banner text
BANNER_TEXT="+------------------------------------------------------------------------------+
             |                                                                              |
             | WARNING                                                                      |
             |                                                                              |
             | The Group's electronic systems, including its communications facilities,     |
             | networks and internet access, are for the use of authorized users and        |
             | provided for official use only. All users are subject to and must comply     |
             | with the Group's Acceptable Use of Information Assets Policy and other       |
             | applicable policies which can be viewed at our internal SharePoint Website.  |
             |                                                                              |
             | Non-compliance with such policies may result in disciplinary action,         |
             | including termination of employment. Use of the Group's electronic systems   |
             | may be monitored and recorded for all lawful purposes, to ensure that their  |
             | use is authorized and in accordance with the applicable policies.            |
             |                                                                              |
             | BY PROCEEDING TO USE THE GROUP'S ELECTRONIC SYSTEMS, YOU ACKNOWLEDGE THAT    |
             | YOU HAVE READ, UNDERSTOOD AND AGREE TO BE BOUND BY THE CONTENTS OF SUCH      |
             | POLICIES.                                                                    |
             |                                                                              |
             +------------------------------------------------------------------------------+"

# Check if the warning banner is already configured
if grep -q "The Group's electronic systems" /etc/issue; then
  echo -e "${GREEN}Warning banners are already configured. Compliant Line 27.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}Warning banners are not configured. Non-Compliant Line 27.${NC}"
  non_compliance_count=$((non_compliance_count + 1))

  # Automatically apply the warning banner to the relevant files
  echo "$BANNER_TEXT" | sudo tee /etc/issue /etc/issue.net /etc/motd > /dev/null
  echo -e "${GREEN}Warning banners have been set. Remediation applied.${NC}"
  compliance_count=$((compliance_count + 1))
fi

echo "Level 28"

# 10. Check unnecessary services and apply remediation if enabled
echo "Checking for unnecessary services... Excel sheet line 28"
for service in xinetd telnet rlogin rsh ypserv ypbind tftp talk ntalk; do
  if systemctl is-enabled --quiet $service; then
    # If the unnecessary service is enabled, print non-compliance in red
    echo -e "${RED}$service is enabled. Non-Compliant Line 28.${NC}"
    non_compliance_count=$((non_compliance_count + 1))

    # Remediation: Disable the service
    echo -e "${RED}Disabling $service...${NC}"
    sudo systemctl disable $service
    sudo systemctl stop $service
    echo -e "${GREEN}$service has been disabled. Remediation applied.${NC}"
    compliance_count=$((compliance_count + 1))

  else
    # If the service is disabled or not installed, print compliance in green
    echo -e "${GREEN}$service is not enabled or not installed. Compliant Line 28.${NC}"
    compliance_count=$((compliance_count + 1))
  fi
done

echo "Level 29"

# 11. Check for inetd service and apply remediation if inactive or missing
echo "Checking for inetd service... Excel sheet line 29"
if systemctl is-active --quiet inetd; then
  # If inetd is active, print non-compliance in red
  echo -e "${RED}inetd is active. Non-Compliant Line 29.${NC}"
  non_compliance_count=$((non_compliance_count + 1))

  # Remediation: Disable the inetd service
  echo -e "${RED}Disabling inetd...${NC}"
  sudo systemctl disable inetd
  sudo systemctl stop inetd
  echo -e "${GREEN}inetd has been disabled. Remediation applied.${NC}"
  compliance_count=$((compliance_count + 1))

else
  # If inetd is inactive or not installed, print compliance in green
  echo -e "${GREEN}inetd is not active or not installed. Compliant Line 29.${NC}"
  compliance_count=$((compliance_count + 1))

  # Remediation: Install inetd (if needed)
  if ! rpm -q xinetd &>/dev/null; then
    echo -e "${RED}inetd is not installed. Installing inetd...${NC}"
    sudo yum install -y xinetd
    echo -e "${GREEN}inetd has been installed. Remediation applied.${NC}"
    compliance_count=$((compliance_count + 1))
  fi
fi

echo "Level 31"

# 1. Check if chrony is installed
echo "Checking if chrony is installed..."
if command -v chronyd >/dev/null 2>&1; then
    echo -e "${GREEN}Chrony is installed. Compliant Line 31.${NC}"
    compliance_count=$((compliance_count + 1))
else
    echo -e "${RED}Chrony is not installed. Non-Compliant Line 31.${NC}"
    non_compliance_count=$((non_compliance_count + 1))

    # Remediation: Install chrony
    echo -e "${RED}Installing chrony...${NC}"
    sudo yum install -y chrony
    if [ $? -eq 0 ]; then
      echo -e "${GREEN}Chrony has been installed. Remediation applied.${NC}"
      compliance_count=$((compliance_count + 1))
    else
      echo -e "${RED}Failed to install chrony. Please check manually.${NC}"
      exit 1
    fi
fi

# 2. Check if chrony service is running
echo "Checking if chrony service is running..."
if systemctl is-active --quiet chronyd; then
    echo -e "${GREEN}Chrony service is running. Compliant Line 31.${NC}"
    compliance_count=$((compliance_count + 1))
else
    echo -e "${RED}Chrony service is not running. Non-Compliant Line 31.${NC}"
    non_compliance_count=$((non_compliance_count + 1))

    # Remediation: Start and enable chrony service
    echo -e "${RED}Starting chrony service and enabling it at boot...${NC}"
    sudo systemctl start chronyd
    sudo systemctl enable chronyd
    if [ $? -eq 0 ]; then
      echo -e "${GREEN}Chrony service has been started and enabled. Remediation applied.${NC}"
      compliance_count=$((compliance_count + 1))
    else
      echo -e "${RED}Failed to start chrony service. Please check manually.${NC}"
      exit 1
    fi
fi

# 3. Check time synchronization status
echo "Checking time synchronization status Line 31 "
if chronyc tracking >/dev/null 2>&1; then
    echo -e "${GREEN}Time synchronization is configured and active. Compliant Line 31.${NC}"
    compliance_count=$((compliance_count + 1))
else
    echo -e "${RED}Time synchronization is not properly configured. Non-Compliant Line 31.${NC}"
    non_compliance_count=$((non_compliance_count + 1))

    # Remediation: Provide instructions for configuring NTP
    # echo -e "${RED}To configure chrony, edit /etc/chrony/chrony.conf to point to your NTP server.${NC}"
    # echo -e "${RED}Example: server <ntp-server-address> iburst.${NC}"
    # echo -e "${RED}Restart chrony service after configuration: sudo systemctl restart chronyd.${NC}"
fi


# echo "Level 32, 33"

# # 1. Check kernel parameters for network security
# echo "Checking network-related kernel parameters..."

# # Disable IP forwarding
# if sysctl net.ipv4.ip_forward | grep -q "= 0"; then
#     echo -e "${GREEN}IP forwarding is disabled. Compliant Line 32, 33.${NC}"
#     compliance_count=$((compliance_count + 1))
# else
#     echo -e "${RED}IP forwarding is enabled. Non-Compliant Line 32, 33.${NC}"
#     non_compliance_count=$((non_compliance_count + 1))
    
#     # Remediation: Disable IP forwarding
#     echo -e "${RED}Disabling IP forwarding...${NC}"
#     sudo sysctl -w net.ipv4.ip_forward=0
#     echo -e "${GREEN}IP forwarding has been disabled. Remediation applied.${NC}"
# fi

# # Enable packet source validation
# if sysctl net.ipv4.conf.all.rp_filter | grep -q "= 1"; then
#     echo -e "${GREEN}Reverse path filtering is enabled. Compliant Line 32, 33.${NC}"
#     compliance_count=$((compliance_count + 1))
# else
#     echo -e "${RED}Reverse path filtering is disabled. Non-Compliant Line 32, 33.${NC}"
#     non_compliance_count=$((non_compliance_count + 1))

#     # Remediation: Enable reverse path filtering
#     echo -e "${RED}Enabling reverse path filtering...${NC}"
#     sudo sysctl -w net.ipv4.conf.all.rp_filter=1
#     echo -e "${GREEN}Reverse path filtering has been enabled. Remediation applied.${NC}"
# fi

# # Disable ICMP redirects
# if sysctl net.ipv4.conf.all.accept_redirects | grep -q "= 0"; then
#     echo -e "${GREEN}ICMP redirects are disabled. Compliant Line 32, 33.${NC}"
#     compliance_count=$((compliance_count + 1))
# else
#     echo -e "${RED}ICMP redirects are enabled. Non-Compliant Line 32, 33.${NC}"
#     non_compliance_count=$((non_compliance_count + 1))

#     # Remediation: Disable ICMP redirects
#     echo -e "${RED}Disabling ICMP redirects...${NC}"
#     sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
#     echo -e "${GREEN}ICMP redirects have been disabled. Remediation applied.${NC}"
# fi

# # 2. Check Access Control List (ACL) configuration
# echo "Checking Access Control Lists (ACLs)..."

# # List the ACLs of important files (/etc/hosts)
# if getfacl /etc/hosts | grep -q "user::rw-"; then
#     echo -e "${GREEN}ACLs for /etc/hosts are correctly configured. Compliant Line 32, 33.${NC}"
#     compliance_count=$((compliance_count + 1))
# else
#     echo -e "${RED}ACLs for /etc/hosts are not configured correctly. Non-Compliant Line 32, 33.${NC}"
#     non_compliance_count=$((non_compliance_count + 1))

#     # Remediation: Set appropriate ACLs
#     echo -e "${RED}Setting correct ACLs for /etc/hosts...${NC}"
#     sudo setfacl -m u:root:rw /etc/hosts
#     echo -e "${GREEN}ACLs have been set. Remediation applied.${NC}"
# fi



echo "Level 34, "

# Function to check and disable IPv6 via GRUB
check_grub_ipv6() {
  echo "Checking if IPv6 is disabled via GRUB..."

  grubfile="/etc/default/grub"  # Default GRUB configuration file

  if grep -q "ipv6.disable=1" "$grubfile"; then
    echo -e "${GREEN}IPv6 is disabled via GRUB configuration. Compliant Line 34, .${NC}"
    compliance_count=$((compliance_count + 1))
  else
    echo -e "${RED}IPv6 is not disabled in GRUB configuration. Non-Compliant Line 34, .${NC}"
    non_compliance_count=$((non_compliance_count + 1))

    # Automatic remediation: Disable IPv6 via GRUB
    echo -e "${RED}Disabling IPv6 in GRUB...${NC}"
    sudo sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="ipv6.disable=1 /' "$grubfile"
    sudo grub2-mkconfig -o /boot/grub2/grub.cfg
    echo -e "${GREEN}IPv6 has been disabled via GRUB configuration. Remediation applied.${NC}"
  fi
}

# Function to check and disable IPv6 via sysctl
check_sysctl_ipv6() {
  echo "Checking if IPv6 is disabled via sysctl settings..."

  if grep -Eqs "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b" /etc/sysctl.conf /etc/sysctl.d/*.conf && \
     grep -Eqs "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b" /etc/sysctl.conf /etc/sysctl.d/*.conf && \
     sysctl net.ipv6.conf.all.disable_ipv6 | grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b"; then
    echo -e "${GREEN}IPv6 is disabled via sysctl settings. Compliant Line 34, .${NC}"
    compliance_count=$((compliance_count + 1))
  else
    echo -e "${RED}IPv6 is not disabled via sysctl settings. Non-Compliant Line 34, .${NC}"
    non_compliance_count=$((non_compliance_count + 1))

    # Automatic remediation: Disable IPv6 via sysctl
    echo -e "${RED}Disabling IPv6 via sysctl settings...${NC}"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
    sudo sysctl -w net.ipv6.route.flush=1
    echo -e "${GREEN}IPv6 has been disabled via sysctl. Remediation applied.${NC}"
  fi
}

# Check DCCP
echo "Checking if DCCP is disabled Line 38 "
if modprobe -n -v dccp | grep "install /bin/true" && ! lsmod | grep -q dccp; then
    echo -e "${GREEN}DCCP is disabled and not loaded. Compliant Line 38.${NC}"
    compliance_count=$((compliance_count + 1))
else
    echo -e "${RED}DCCP is not properly disabled or loaded. Non-Compliant Line 38.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
    echo "Run the following command to disable DCCP:"
    echo "echo 'install dccp /bin/true' | sudo tee /etc/modprobe.d/dccp.conf"
    echo "sudo modprobe -r dccp"
fi

# Check SCTP
echo "Checking if SCTP is disabled Line 39 "
if modprobe -n -v sctp | grep "install /bin/true" && ! lsmod | grep -q sctp; then
    echo -e "${GREEN}SCTP is disabled and not loaded. Compliant Line 39.${NC}"
    compliance_count=$((compliance_count + 1))
else
    echo -e "${RED}SCTP is not properly disabled or loaded. Non-Compliant Line 39.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
    echo "Run the following command to disable SCTP:"
    echo "echo 'install sctp /bin/true' | sudo tee /etc/modprobe.d/sctp.conf"
    echo "sudo modprobe -r sctp"
fi

# Check RDS
echo "Checking if RDS is disabled Line 40 "
if modprobe -n -v rds | grep "install /bin/true" && ! lsmod | grep -q rds; then
    echo -e "${GREEN}RDS is disabled and not loaded. Compliant Line 40.${NC}"
    compliance_count=$((compliance_count + 1))
else
    echo -e "${RED}RDS is not properly disabled or loaded. Non-Compliant Line 40.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
    echo "Run the following command to disable RDS:"
    echo "echo 'install rds /bin/true' | sudo tee /etc/modprobe.d/rds.conf"
    echo "sudo modprobe -r rds"
fi

# Check TIPC
echo "Checking if TIPC is disabled 41"
if modprobe -n -v tipc | grep "install /bin/true" && ! lsmod | grep -q tipc; then
    echo -e "${GREEN}TIPC is disabled and not loaded. Compliant Line 41.${NC}"
    compliance_count=$((compliance_count + 1))
else
    echo -e "${RED}TIPC is not properly disabled or loaded. Non-Compliant Line 41.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
    echo "Run the following command to disable TIPC:"
    echo "echo 'install tipc /bin/true' | sudo tee /etc/modprobe.d/tipc.conf"
    echo "sudo modprobe -r tipc"
fi

# # 3. Check firewall status
# echo "Checking firewall status Line 42"

# if systemctl is-active firewalld >/dev/null 2>&1 || systemctl is-active iptables >/dev/null 2>&1; then
#     echo -e "${GREEN}Firewall is active. Compliant Line 42.${NC}"
#     compliance_count=$((compliance_count + 1))
# else
#     echo -e "${RED}Firewall is not active. Non-Compliant Line 42.${NC}"
#     non_compliance_count=$((non_compliance_count + 1))

#     # Remediation: Activate the firewall
#     echo -e "${RED}Activating firewall...${NC}"
#     sudo systemctl enable --now firewalld || sudo systemctl enable --now iptables
#     echo -e "${GREEN}Firewall has been activated. Remediation applied.${NC}"
# fi



# echo "Firewall Configuration - Level 43"

# # 1. Ensure the firewall is active
# echo "Checking if firewalld or iptables is active..."

# if systemctl is-active firewalld >/dev/null 2>&1; then
#     echo -e "${GREEN}Firewalld is active. Compliant Line 43.${NC}"
#     compliance_count=$((compliance_count + 1))
# elif systemctl is-active iptables >/dev/null 2>&1; then
#     echo -e "${GREEN}Iptables is active. Compliant Line 43.${NC}"
#     compliance_count=$((compliance_count + 1))
# else
#     echo -e "${RED}Neither firewalld nor iptables is active. Non-Compliant Line 43.${NC}"
#     non_compliance_count=$((non_compliance_count + 1))
    
#     # Automatic remediation: Enable firewalld
#     echo -e "${RED}Enabling firewalld...${NC}"
#     sudo systemctl enable --now firewalld
#     if [ $? -eq 0 ]; then
#         echo -e "${GREEN}Firewalld is now active and enabled. Remediation applied.${NC}"
#         compliance_count=$((compliance_count + 1))
#     else
#         echo -e "${RED}Failed to enable firewalld. Trying iptables...${NC}"
#         sudo systemctl enable --now iptables
#         if [ $? -eq 0 ]; then
#             echo -e "${GREEN}Iptables is now active and enabled. Remediation applied.${NC}"
#             compliance_count=$((compliance_count + 1))
#         else
#             echo -e "${RED}Failed to enable iptables. Please manually configure the firewall.${NC}"
#         fi
#     fi
# fi

# # 2. Ensure only necessary ports are open
# echo "Configuring necessary ports..."

# # Open common service ports
# sudo firewall-cmd --permanent --add-service=ssh
# sudo firewall-cmd --permanent --add-service=http
# sudo firewall-cmd --permanent --add-service=https
# sudo firewall-cmd --permanent --add-service=dns

# # Reload firewalld to apply changes
# sudo firewall-cmd --reload

# if [ $? -eq 0 ]; then
#     echo -e "${GREEN}Necessary ports have been configured and opened. Compliant Line 43.${NC}"
#     compliance_count=$((compliance_count + 1))
# else
#     echo -e "${RED}Failed to configure necessary ports. Non-Compliant Line 43.${NC}"
#     non_compliance_count=$((non_compliance_count + 1))
# fi

# # 3. Disable unused services and ports
# echo "Disabling unused ports..."

# # Remove unnecessary services
# sudo firewall-cmd --permanent --remove-service=ftp
# sudo firewall-cmd --permanent --remove-service=telnet
# sudo firewall-cmd --permanent --remove-service=samba

# # Reload firewalld to apply changes
# sudo firewall-cmd --reload

# if [ $? -eq 0 ]; then
#     echo -e "${GREEN}Unused ports and services have been disabled. Compliant Line 43.${NC}"
#     compliance_count=$((compliance_count + 1))
# else
#     echo -e "${RED}Failed to disable unused ports and services. Non-Compliant Line 43.${NC}"
#     non_compliance_count=$((non_compliance_count + 1))
# fi

# # 4. Check if the default zone is set to block unused traffic
# echo "Checking if the default zone is set to block..."

# default_zone=$(sudo firewall-cmd --get-default-zone)
# if [[ "$default_zone" == "block" ]]; then
#     echo -e "${GREEN}Default zone is set to block. Compliant Line 43.${NC}"
#     compliance_count=$((compliance_count + 1))
# else
#     echo -e "${RED}Default zone is not set to block. Non-Compliant Line 43.${NC}"
#     non_compliance_count=$((non_compliance_count + 1))

#     # Automatic remediation: Set default zone to block
#     echo -e "${RED}Setting default zone to block...${NC}"
#     sudo firewall-cmd --set-default-zone=block
#     echo -e "${GREEN}Default zone set to block. Remediation applied.${NC}"
# fi



# echo "Level 45"

# # 23. Configure nftables
# echo "Checking nftables configuration..."
# NFTABLES_FILE="/etc/nftables/nftables.rules"

# if [ -f "$NFTABLES_FILE" ]; then
#     echo -e "${GREEN}nftables configuration file found at $NFTABLES_FILE. Compliant Line 45.${NC}"
#     compliance_count=$((compliance_count + 1))
# else
#     echo -e "${RED}nftables configuration file not found. Non-Compliant Line 45.${NC}"
#     non_compliance_count=$((non_compliance_count + 1))
#     # Automatic remediation: Create nftables configuration file
#     echo "Creating nftables configuration file..."
#     sudo nft list ruleset > "$NFTABLES_FILE"
#     if [ $? -eq 0 ]; then
#         echo -e "${GREEN}nftables configuration file created at $NFTABLES_FILE. Remediation applied.${NC}"
#     else
#         echo -e "${RED}Failed to create nftables configuration file. Manual intervention needed.${NC}"
#     fi
# fi

# echo "Level 46"

# # 24. Configure iptables
# echo "Checking iptables configuration..."
# if iptables -L | grep "Chain INPUT (policy DROP)" > /dev/null; then
#     echo -e "${GREEN}iptables is correctly configured with default DROP policy. Compliant Line 46.${NC}"
#     compliance_count=$((compliance_count + 1))
# else
#     echo -e "${RED}iptables is not correctly configured. Non-Compliant Line 46.${NC}"
#     non_compliance_count=$((non_compliance_count + 1))

#     # Automatic remediation: Configure iptables
#     echo "Configuring iptables with a default DROP policy..."
#     sudo iptables -F
#     sudo iptables -P INPUT DROP
#     sudo iptables -P OUTPUT DROP
#     sudo iptables -P FORWARD DROP
#     sudo iptables -A INPUT -i lo -j ACCEPT
#     sudo iptables -A OUTPUT -o lo -j ACCEPT
#     sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP
#     sudo iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
#     sudo iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
#     sudo iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
#     sudo iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
#     sudo iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
#     sudo iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
#     sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
    
#     if [ $? -eq 0 ]; then
#         echo -e "${GREEN}iptables has been configured with a default DROP policy. Remediation applied.${NC}"
#     else
#         echo -e "${RED}Failed to configure iptables. Manual intervention needed.${NC}"
#     fi
# fi


# echo " Level 47"

# # Check if IPv4 iptables rules are configured
# echo "Checking if there are any IPv4 iptables rules..."
 
# ipv4_rules=$(iptables -S)  
 
# if [[ -n "$ipv4_rules" ]]; then
#   echo -e "${GREEN}IPv4 iptables rules are configured Compliant Line 47:${NC}"
#   echo "$ipv4_rules" 
# else
#   echo -e "${RED}No IPv4 iptables rules found Non-Compliant Line 47.${NC}"
# fi 
# Configure IPv4 iptables
# echo "Checking IPv4 iptables..."
 
# Flush existing iptables rules
# iptables -F
 
# # Set default policies to DROP
# iptables -P INPUT DROP
# iptables -P OUTPUT DROP
# iptables -P FORWARD DROP
 
# # Allow loopback traffic
# iptables -A INPUT -i lo -j ACCEPT
# iptables -A OUTPUT -o lo -j ACCEPT
# iptables -A INPUT -s 127.0.0.0/8 -j DROP
 
# Allow outbound and established connections
# iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
# iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
# iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
# iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
# iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
# iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
 
# Allow inbound SSH on port 22
# iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# echo "Level 51"

# # 1. Checking audit rules for changes to system administration scope (sudoers)
# echo "Checking audit rules for changes to system administration scope (sudoers)..."
# if auditctl -l | grep -q "/etc/sudoers"; then
#   echo -e "${GREEN}Sudoers changes are being audited. This is compliant Line 51.${NC}"
#   compliance_count=$((compliance_count + 1))
# else
#   echo -e "${RED}Sudoers changes are not being audited. This is not compliant Line 51. Adding the necessary rules...${NC}"
#   non_compliance_count=$((non_compliance_count + 1))
  
#   # Automatic remediation: Add audit rules for sudoers
#   echo "Adding audit rules for /etc/sudoers and /etc/sudoers.d..."
#   sudo bash -c 'echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/50-scope.rules'
#   sudo bash -c 'echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/50-scope.rules'
#   sudo auditctl -R /etc/audit/rules.d/50-scope.rules
#   echo -e "${GREEN}Audit rules for sudoers changes have been added. Remediation applied.${NC}"
# fi

echo "Level 52"

# 2. Checking audit rules for login and logout events
echo "Checking audit rules for login and logout events..."
if auditctl -l | grep -q "/var/log/lastlog"; then
  echo -e "${GREEN}Login and logout events are being audited. This is compliant Line 52.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}Login and logout events are not being audited. This is not compliant Line 52. Adding the necessary rules...${NC}"
  non_compliance_count=$((non_compliance_count + 1))
  
  # Automatic remediation: Add audit rules for login/logout events
  echo "Adding audit rules for /var/log/lastlog and /var/run/faillock/..."
  sudo bash -c 'echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/50-logins.rules'
  sudo bash -c 'echo "-w /var/run/faillock/ -p wa -k logins" >> /etc/audit/rules.d/50-logins.rules'
  sudo auditctl -R /etc/audit/rules.d/50-logins.rules
  echo -e "${GREEN}Audit rules for login and logout events have been added. Remediation applied.${NC}"
fi


echo "Level 53"

# 1. Checking audit rules for session initiation information
echo "Checking audit rules for session initiation information..."
if auditctl -l | grep -q "/var/run/utmp"; then
  echo -e "${GREEN}Session initiation events are being audited. This is compliant Line 53.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}Session initiation events are not being audited. This is not compliant Line 53.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
  
  # Automatic remediation: Add audit rules for session initiation
  echo "Adding audit rules for session initiation events..."
  sudo bash -c 'echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/50-session.rules'
  sudo bash -c 'echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/50-session.rules'
  sudo bash -c 'echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/50-session.rules'
  sudo auditctl -R /etc/audit/rules.d/50-session.rules
  echo -e "${GREEN}Audit rules for session initiation events have been added. Remediation applied.${NC}"
fi

echo "Level 54 - Checking Date and Time Modification Events"

# Check and remediate audit rules for 32-bit systems
check_audit_32bit() {
    echo "Checking audit rules for 32-bit system..."
    if grep -q "time-change" /etc/audit/rules.d/*.rules && auditctl -l | grep -q "time-change"; then
        if auditctl -l | grep -q "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" && \
           auditctl -l | grep -q "-a always,exit -F arch=b32 -S clock_settime -k time-change" && \
           auditctl -l | grep -q "-w /etc/localtime -p wa -k time-change"; then
            echo -e "${GREEN}Date and time modification events are being audited for 32-bit system. Compliant Line 54.${NC}"
            compliance_count=$((compliance_count + 1))
        else
            echo -e "${RED}Audit rules for date and time modification are missing or incorrect on 32-bit system. Non-Compliant Line 54.${NC}"
            non_compliance_count=$((non_compliance_count + 1))

            # Remediation: Add the correct audit rules
            echo "Adding audit rules for 32-bit system..."
            sudo bash -c 'echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/50-time_change.rules'
            sudo bash -c 'echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/50-time_change.rules'
            sudo bash -c 'echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/50-time_change.rules'
            sudo auditctl -R /etc/audit/rules.d/50-time_change.rules
            echo -e "${GREEN}Audit rules for 32-bit system have been added. Remediation applied.${NC}"
        fi
    else
        echo -e "${RED}Audit rules for date and time modification events are not present on 32-bit system. Non-Compliant Line 54.${NC}"
        non_compliance_count=$((non_compliance_count + 1))
    fi
}

# Check and remediate audit rules for 64-bit systems
check_audit_64bit() {
    echo "Checking audit rules for 64-bit system..."
    if grep -q "time-change" /etc/audit/rules.d/*.rules && auditctl -l | grep -q "time-change"; then
        if auditctl -l | grep -q "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" && \
           auditctl -l | grep -q "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" && \
           auditctl -l | grep -q "-a always,exit -F arch=b64 -S clock_settime -k time-change" && \
           auditctl -l | grep -q "-a always,exit -F arch=b32 -S clock_settime -k time-change" && \
           auditctl -l | grep -q "-w /etc/localtime -p wa -k time-change"; then
            echo -e "${GREEN}Date and time modification events are being audited for 64-bit system. Compliant Line 54.${NC}"
            compliance_count=$((compliance_count + 1))
        else
            echo -e "${RED}Audit rules for date and time modification are missing or incorrect on 64-bit system. Non-Compliant Line 54.${NC}"
            non_compliance_count=$((non_compliance_count + 1))

            # Remediation: Add the correct audit rules
            echo "Adding audit rules for 64-bit system..."
            sudo bash -c 'echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/50-time_change.rules'
            sudo bash -c 'echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/50-time_change.rules'
            sudo bash -c 'echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/50-time_change.rules'
            sudo bash -c 'echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/50-time_change.rules'
            sudo bash -c 'echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/50-time_change.rules'
            sudo auditctl -R /etc/audit/rules.d/50-time_change.rules
            echo -e "${GREEN}Audit rules for 64-bit system have been added. Remediation applied.${NC}"
        fi
    else
        echo -e "${RED}Audit rules for date and time modification events are not present on 64-bit system. Non-Compliant Line 54.${NC}"
        non_compliance_count=$((non_compliance_count + 1))
    fi
}

# Determine if the system is 32-bit or 64-bit and run the appropriate check
if [[ $(uname -m) == "x86_64" ]]; then
    check_audit_64bit
else
    check_audit_32bit
fi


echo " Level 55"

echo "Checking audit rules for Mandatory Access Control (SELinux/AppArmor) modifications..."

# Check if audit rules for MAC policy changes are in place
if auditctl -l | grep -q "MAC-policy"; then
  echo -e "${GREEN}MAC policy changes are being audited. Compliant Line 55.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}MAC policy changes are not being audited. Non-Compliant Line 55.${NC}"
  non_compliance_count=$((non_compliance_count + 1))

  # Remediation: Add the necessary audit rules
  echo "Adding audit rules for MAC policy changes..."
  sudo bash -c 'echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/50-MAC_policy.rules'
  sudo bash -c 'echo "-w /usr/share/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/50-MAC_policy.rules'
  
  # Load the rules into auditd
  sudo auditctl -R /etc/audit/rules.d/50-MAC_policy.rules

  # Verify if the rules have been successfully applied
  if auditctl -l | grep -q "MAC-policy"; then
    echo -e "${GREEN}Audit rules for MAC policy changes have been successfully added. Compliant Line 55.${NC}"
    compliance_count=$((compliance_count + 1))
  else
    echo -e "${RED}Failed to apply audit rules for MAC policy changes. Still Non-Compliant Line 55.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
  fi
fi



echo "Level 56"
echo "Checking audit rules for system's Mandatory Access Controls (MAC)..."
 
# Check and apply audit rules for 32-bit system
echo "Checking audit rules for 32-bit system..."
if grep -q "system-locale" /etc/audit/rules.d/*.rules && auditctl -l | grep -q "arch=b32"; then
    if auditctl -l | grep -q "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" && \
       auditctl -l | grep -q "-w /etc/issue -p wa -k system-locale" && \
       auditctl -l | grep -q "-w /etc/issue.net -p wa -k system-locale" && \
       auditctl -l | grep -q "-w /etc/hosts -p wa -k system-locale" && \
       auditctl -l | grep -q "-w /etc/sysconfig/network -p wa -k system-locale"; then
        echo -e "${GREEN}Mandatory Access Control events are being audited for 32-bit system. Compliant Line 56.${NC}"
        compliance_count=$((compliance_count + 1))
    else
        echo -e "${RED}Audit rules for MAC modification are missing or incorrect on 32-bit system. Non-Compliant Line 56.${NC}"
        non_compliance_count=$((non_compliance_count + 1))
        # Remediation: Add audit rules for 32-bit system
        echo "Adding MAC audit rules for 32-bit system..."
        sudo bash -c 'echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/50-mac.rules'
        sudo bash -c 'echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/50-mac.rules'
        sudo bash -c 'echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/50-mac.rules'
        sudo bash -c 'echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/50-mac.rules'
        sudo bash -c 'echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/50-mac.rules'
        sudo systemctl restart auditd  # Apply the changes immediately
    fi
else
    echo -e "${RED}Audit rules for MAC modification events are not present on 32-bit system. Non-Compliant Line 56.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
fi
 
# Check and apply audit rules for 64-bit system
echo "Checking audit rules for 64-bit system..."
if grep -q "system-locale" /etc/audit/rules.d/*.rules && auditctl -l | grep -q "arch=b64"; then
    if auditctl -l | grep -q "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" && \
       auditctl -l | grep -q "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" && \
       auditctl -l | grep -q "-w /etc/issue -p wa -k system-locale" && \
       auditctl -l | grep -q "-w /etc/issue.net -p wa -k system-locale" && \
       auditctl -l | grep -q "-w /etc/hosts -p wa -k system-locale" && \
       auditctl -l | grep -q "-w /etc/sysconfig/network -p wa -k system-locale"; then
        echo -e "${GREEN}Mandatory Access Control events are being audited for 64-bit system. Compliant Line 56.${NC}"
        compliance_count=$((compliance_count + 1))
    else
        echo -e "${RED}Audit rules for MAC modification are missing or incorrect on 64-bit system. Non-Compliant Line 56.${NC}"
        non_compliance_count=$((non_compliance_count + 1))
        # Remediation: Add audit rules for 64-bit system
        echo "Adding MAC audit rules for 64-bit system..."
        sudo bash -c 'echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/50-mac.rules'
        sudo bash -c 'echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/50-mac.rules'
        sudo bash -c 'echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/50-mac.rules'
        sudo bash -c 'echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/50-mac.rules'
        sudo bash -c 'echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/50-mac.rules'
        sudo bash -c 'echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/50-mac.rules'
        sudo systemctl restart auditd  # Apply the changes immediately
    fi
else
    echo -e "${RED}Audit rules for MAC modification events are not present on 64-bit system. Non-Compliant Line 56.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
fi
 
# Restart auditd to apply the changes
echo "Restarting auditd to apply changes..."
sudo systemctl restart auditd
 
# Verify if the rules have been successfully applied
if auditctl -l | grep -q "system-locale"; then
    echo -e "${GREEN}Audit rules for MAC modification events have been successfully applied. Compliant Line 56.${NC}"
    compliance_count=$((compliance_count + 1))
else
    echo -e "${RED}Failed to apply audit rules for MAC modification events. Still Non-Compliant Line 56.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
fi
 
# Verify output of audit rules for both systems
echo "Verifying audit rules for MAC on 32-bit system..."
grep system-locale /etc/audit/rules.d/*.rules
 
echo "Verifying audit rules for MAC on 64-bit system..."
auditctl -l | grep system-locale

echo " Level 57"
echo "Checking audit rules for discretionary access control permission modification events..."

# Function to check if audit rules exist for 32-bit system
check_audit_32bit_perm_mod() {
    if grep -q "perm_mod" /etc/audit/rules.d/*.rules && auditctl -l | grep -q "perm_mod"; then
        if auditctl -l | grep -q "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod" && \
           auditctl -l | grep -q "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod" && \
           auditctl -l | grep -q "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod"; then
            echo -e "${GREEN}Permission modification events are being audited on 32-bit system. Compliant Line 57.${NC}"
            compliance_count=$((compliance_count + 1))
        else
            echo -e "${RED}Audit rules for permission modification are missing or incorrect on 32-bit system. Non-Compliant Line 57.${NC}"
            non_compliance_count=$((non_compliance_count + 1))
            # Apply remediation
            auditctl -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
            auditctl -a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod
            auditctl -a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
        fi
    else
        echo -e "${RED}Audit rules for permission modification events are not present on 32-bit system. Non-Compliant Line 57.${NC}"
        non_compliance_count=$((non_compliance_count + 1))
    fi
}

# Function to check if audit rules exist for 64-bit system
check_audit_64bit_perm_mod() {
    if grep -q "perm_mod" /etc/audit/rules.d/*.rules && auditctl -l | grep -q "perm_mod"; then
        if auditctl -l | grep -q "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod" && \
           auditctl -l | grep -q "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod" && \
           auditctl -l | grep -q "-a always,exit -F arch=b64 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod" && \
           auditctl -l | grep -q "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod" && \
           auditctl -l | grep -q "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod" && \
           auditctl -l | grep -q "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod"; then
            echo -e "${GREEN}Permission modification events are being audited on 64-bit system. Compliant Line 57.${NC}"
            compliance_count=$((compliance_count + 1))
        else
            echo -e "${RED}Audit rules for permission modification are missing or incorrect on 64-bit system. Non-Compliant Line 57.${NC}"
            non_compliance_count=$((non_compliance_count + 1))
            # Apply remediation
            auditctl -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
            auditctl -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
            auditctl -a always,exit -F arch=b64 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod
            auditctl -a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod
            auditctl -a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
            auditctl -a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
        fi
    else
        echo -e "${RED}Audit rules for permission modification events are not present on 64-bit system. Non-Compliant Line 57.${NC}"
        non_compliance_count=$((non_compliance_count + 1))
    fi
}

# Determine if system is 32-bit or 64-bit and run appropriate check
if [[ $(uname -m) == "x86_64" ]]; then
    check_audit_64bit_perm_mod
else
    check_audit_32bit_perm_mod
fi


echo " Level 58"

echo "Checking audit rules for unsuccessful unauthorized file access attempts..."
# Function to check audit rules
check_audit_access_rules() {
    if auditctl -l | grep -q "access"; then
        echo -e "${GREEN}Unauthorized file access attempts are being audited Line 58 Compliant.${NC}"
        compliance_count=$((compliance_count + 1))
    else
        echo -e "${RED}Unauthorized file access attempts are not being audited Line 58 Non-Compliant.${NC}"
        non_compliance_count=$((non_compliance_count + 1))

        # Apply the audit rules directly
        auditctl -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
        auditctl -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
        auditctl -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
        auditctl -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
        echo -e "${GREEN}Audit rules for unauthorized file access attempts have been applied.${NC}"
    fi
}

# Function to verify the audit rules
verify_audit_rules() {
    # For 32-bit system
    echo "Checking audit rules for 32-bit system..."
    if grep -q 'access' /etc/audit/rules.d/*.rules && auditctl -l | grep -q 'access'; then
        echo -e "${GREEN}32-bit audit rules for unauthorized file access attempts are configured properly Compliant Line 58 .${NC}"
        compliance_count=$((compliance_count + 1))
    else
        echo -e "${RED}32-bit audit rules for unauthorized file access attempts are missing Line 58 Non-Compliant .${NC}"
        non_compliance_count=$((non_compliance_count + 1))
        auditctl -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
        auditctl -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
        echo -e "${GREEN}32-bit audit rules have been applied.${NC}"
    fi

    # For 64-bit system
    echo "Checking audit rules for 64-bit system..."
    if grep -q 'access' /etc/audit/rules.d/*.rules && auditctl -l | grep -q 'access'; then
        echo -e "${GREEN}64-bit audit rules for unauthorized file access attempts are configured properly Line 58 Compliant .${NC}"
        compliance_count=$((compliance_count + 1))
    else
        echo -e "${RED}64-bit audit rules for unauthorized file access attempts are missing Line 58 Non-Compliant .${NC}"
        non_compliance_count=$((non_compliance_count + 1))
        auditctl -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
        auditctl -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
        echo -e "${GREEN}64-bit audit rules have been applied.${NC}"
    fi
}


echo " Level 59"
echo "Checking audit rules for user/group information modification events..."

# Function to check if audit rules exist for user/group information modification
check_audit_identity() {
    # Check if rules are present in auditd rules files
    if grep -q "identity" /etc/audit/rules.d/*.rules && auditctl -l | grep -q "identity"; then
        # Verify that all required rules are present
        if auditctl -l | grep -q -E '-w /etc/(group|passwd|gshadow|shadow|security/opasswd) -p wa -k identity'; then
            echo -e "${GREEN}User/group information modification events are being audited. Compliant Line 59.${NC}"
            compliance_count=$((compliance_count + 1))
        else
            echo -e "${RED}Audit rules for user/group modification events are missing or incorrect. Non-Compliant Line 59.${NC}"
            non_compliance_count=$((non_compliance_count + 1))
            # Remediation suggestions
            echo "Add the following lines to /etc/audit/rules.d/50-identity.rules:"
            echo "-w /etc/group -p wa -k identity"
            echo "-w /etc/passwd -p wa -k identity"
            echo "-w /etc/gshadow -p wa -k identity"
            echo "-w /etc/shadow -p wa -k identity"
            echo "-w /etc/security/opasswd -p wa -k identity"
        fi
    else
        echo -e "${RED}Audit rules for user/group modification events are not present. Non-Compliant Line 59.${NC}"
        non_compliance_count=$((non_compliance_count + 1))
        # Remediation suggestions
        echo "Add the following lines to /etc/audit/rules.d/50-identity.rules:"
        echo "-w /etc/group -p wa -k identity"
        echo "-w /etc/passwd -p wa -k identity"
        echo "-w /etc/gshadow -p wa -k identity"
        echo "-w /etc/shadow -p wa -k identity"
        echo "-w /etc/security/opasswd -p wa -k identity"
    fi
}

echo "Level 60"

echo "Checking audit rules for successful file system mounts..."
 
# Check and apply audit rules for 32-bit system
echo "Checking audit rules for 32-bit system..."
if grep -q "arch=b32.*mount" /etc/audit/rules.d/*.rules && auditctl -l | grep -q "arch=b32.*mount"; then
    echo -e "${GREEN}32-bit audit rules for successful file system mounts are configured. Compliant Line 60.${NC}"
    compliance_count=$((compliance_count + 1))
else
    echo -e "${RED}32-bit audit rules for successful file system mounts are missing. Non-Compliant Line 60.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
    echo "Adding audit rules for 32-bit mounts..."
    sudo bash -c 'echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/50-mount.rules'
fi
 
# Check and apply audit rules for 64-bit system
echo "Checking audit rules for 64-bit system..."
if grep -q "arch=b64.*mount" /etc/audit/rules.d/*.rules && auditctl -l | grep -q "arch=b64.*mount"; then
    echo -e "${GREEN}64-bit audit rules for successful file system mounts are configured. Compliant Line 60.${NC}"
    compliance_count=$((compliance_count + 1))
else
    echo -e "${RED}64-bit audit rules for successful file system mounts are missing. Non-Compliant Line 60.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
    echo "Adding audit rules for 64-bit mounts..."
    sudo bash -c 'echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/50-mount.rules'
fi
 
# Restart auditd to apply the new rules
echo "Restarting auditd to apply the changes..."
sudo systemctl restart auditd
 
# Recheck if the audit rules have been successfully applied
echo "Rechecking audit rules..."
if auditctl -l | grep -q "mount"; then
    echo -e "${GREEN}Audit rules for file system mounts have been successfully applied. Compliant Line 60.${NC}"
    compliance_count=$((compliance_count + 1))
else
    echo -e "${RED}Failed to apply audit rules for file system mounts. Still Non-Compliant Line 60.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
fi
 
# Verify audit rules in /etc/audit/rules.d/ directory
echo "Verifying /etc/audit/rules.d/ contents..."
grep mounts /etc/audit/rules.d/*.rules



echo " Level 62"

echo "Checking audit rules for file deletion events..."

# Check if audit rules for file deletion events are present
if auditctl -l | grep -q "delete"; then
  echo -e "${GREEN}File deletion events are being audited. Compliant Line 62.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}File deletion events are not being audited. Non-Compliant Line 62. Adding the following rules:${NC}"
  non_compliance_count=$((non_compliance_count + 1))

  # Remediation: Adding audit rules for file deletion events
  echo "Adding file deletion audit rules..."
  sudo bash -c 'echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/50-deletion.rules'
  sudo bash -c 'echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/50-deletion.rules'

  # Restart auditd to apply the new rules
  sudo systemctl restart auditd

  # Verify if the rules have been successfully applied
  if auditctl -l | grep -q "delete"; then
    echo -e "${GREEN}File deletion audit rules have been successfully applied. Compliant Line 62.${NC}"
    compliance_count=$((compliance_count + 1))
  else
    echo -e "${RED}Failed to apply file deletion audit rules. Still Non-Compliant Line 62.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
  fi
fi


echo " Level 63"

echo "Checking audit rules for kernel module loading/unloading..."

# Check if audit rules for kernel module loading/unloading are present
if auditctl -l | grep -q "modules"; then
  echo -e "${GREEN}Kernel module loading/unloading events are being audited. Compliant Line 63.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}Kernel module loading/unloading events are not being audited. Non-Compliant Line 63. Add the following rules:${NC}"
  non_compliance_count=$((non_compliance_count + 1))

  # Remediation: Adding audit rules for kernel module events
  echo "Adding kernel module audit rules..."
  echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/rules.d/50-modules.rules
  echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/50-modules.rules
  echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/50-modules.rules
  echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/50-modules.rules
  echo "-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/50-modules.rules
fi

echo " Level 64"

echo "Checking if sudo log auditing is configured..."
 
# Extract sudo log path from sudoers
sudo_logfile=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' | tr -d '"')
 
if [ -z "$sudo_logfile" ]; then
  echo -e "${RED}No sudo log file found. Please ensure sudo is configured to log actions.${NC}"
else
  echo "Sudo log file: $sudo_logfile"
  if auditctl -l | grep -q "$sudo_logfile"; then
    echo -e "${GREEN}Sudo log file ($sudo_logfile) is being audited. Compliant Line 64.${NC}"
    compliance_count=$((compliance_count + 1))
  else
    echo -e "${RED}Sudo log file is not being audited. Non-Compliant Line 64.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
    
    # Add audit rule for sudo log file
    echo "-w $sudo_logfile -p wa -k actions" >> /etc/audit/rules.d/50-actions.rules
    echo "Rule added for $sudo_logfile."
  fi
fi

echo " Level 65"

echo "Ensuring audit configuration is immutable..."

# Check if audit configuration is immutable
if auditctl -s | grep -q "enabled.*2"; then
  echo -e "${GREEN}Audit configuration is already immutable. Compliant Line 65.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}Audit configuration is not immutable. Non-Compliant Line 65.${NC}"
  non_compliance_count=$((non_compliance_count + 1))

  # Remediation: Add the rule to make the audit config immutable
  echo "Setting audit configuration to immutable..."
  sudo bash -c 'echo "-e 2" >> /etc/audit/rules.d/99-finalize.rules'
  
  # Restart auditd to apply changes
  sudo systemctl restart auditd

  # Verify if the configuration was updated
  if auditctl -s | grep -q "enabled.*2"; then
    echo -e "${GREEN}Audit configuration is now set to immutable. Compliant Line 65.${NC}"
    compliance_count=$((compliance_count + 1))
  else
    echo -e "${RED}Failed to set audit configuration to immutable. Still Non-Compliant Line 65.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
  fi

  echo "A system reboot is recommended for this change to take full effect."
fi



echo " Level 66"

echo "Checking if auditing is enabled..."
 
# Check if auditing is enabled
if auditctl -s | grep -q "enabled.*1"; then
  echo -e "${GREEN}Auditing is enabled. Compliant Line 66.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}Auditing is not enabled. Non-Compliant Line 66. Please enable auditing manually or configure auditd to start on boot.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
fi


echo " Level 67"

# 13. Check auditd installation
echo "Checking auditd installation..."
if rpm -q audit &> /dev/null; then
  # If auditd is installed, print compliance message
  echo -e "${GREEN}Auditd is installed. Compliant Line 67.${NC}"
  compliance_count=$((compliance_count + 1))
else
  # If auditd is not installed, print non-compliance message
  echo -e "${RED}Auditd is not installed. Non-Compliant Line 67.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
  
  # Suggest remediation
  echo "Auditd is not installed. Installing auditd..."
  
  # Remediation: Install auditd
  sudo yum install -y audit

  # Verify if installation was successful
  if rpm -q audit &> /dev/null; then
    echo -e "${GREEN}Auditd has been successfully installed. Now compliant.${NC}"
    compliance_count=$((compliance_count + 1))
  else
    echo -e "${RED}Failed to install auditd. Still non-compliant.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
  fi
fi



echo " Level 68"

echo "Checking if auditd service is enabled..."
 
# Verify that auditd is enabled
if systemctl is-enabled auditd | grep -q "enabled"; then
  echo -e "${GREEN}Auditd service is enabled and running. Compliant Line 68.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}Auditd service is not enabled. Non-Compliant Line 68. Please verify manually.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
fi

echo " Level 69"
echo "Checking audit for processes prior to auditd startup is enabled..."

# Add audit=1 to GRUB configuration
if grep -q "audit=1" /etc/default/grub; then
  echo -e "${GREEN}Audit setting already exists in GRUB. Compliant Line 69.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}Audit setting does not exist. Non-Compliant Line 69.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
  echo "Adding audit=1 to GRUB configuration..."
  sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit=1"/' /etc/default/grub
fi

# Update GRUB configuration
grub2-mkconfig -o /boot/grub2/grub.cfg

# Verify the GRUB configuration for audit=1
if grep -E 'kernelopts=(\S+\s+)*audit=1\b' /boot/grub2/grubenv; then
  echo -e "${GREEN}Audit setting found in GRUB environment. Compliant Line 69.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}Audit setting not found in GRUB environment. Non-Compliant Line 69.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
fi

echo " Level 70"
echo "Ensuring audit_backlog_limit is sufficient..."

# Define desired backlog limit size (change as needed)
BACKLOG_SIZE=8192

# Add audit_backlog_limit to GRUB configuration
if grep -q "audit_backlog_limit=" /etc/default/grub; then
  echo -e "${GREEN}Audit backlog limit already exists in GRUB. Compliant Line 70.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}Audit_backlog_limit not in GRUB configuration. Non-Compliant Line 70.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
  
  # Remediation: Add audit_backlog_limit to GRUB configuration
  echo "Adding audit_backlog_limit=$BACKLOG_SIZE to GRUB configuration..."
  sudo sed -i "s/GRUB_CMDLINE_LINUX=\"\(.*\)\"/GRUB_CMDLINE_LINUX=\"\1 audit_backlog_limit=$BACKLOG_SIZE\"/" /etc/default/grub

  # Update GRUB configuration
  sudo grub2-mkconfig -o /boot/grub2/grub.cfg
fi

# Verify audit_backlog_limit in GRUB environment
if grep -E "kernelopts=(\S+\s+)*audit_backlog_limit=\S+\b" /boot/grub2/grubenv; then
  echo -e "${GREEN}Audit backlog limit is configured in GRUB environment. Compliant Line 70.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}Audit backlog limit not configured in GRUB environment. Non-Compliant Line 70.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
  
  # Remediation: Apply audit_backlog_limit in GRUB environment
  echo "Reconfiguring GRUB to apply audit_backlog_limit..."
  
  # Ensure GRUB configuration is properly applied
  sudo grub2-mkconfig -o /boot/grub2/grub.cfg
  
  # Recheck to verify if it has been applied
  if grep -E "kernelopts=(\S+\s+)*audit_backlog_limit=\S+\b" /boot/grub2/grubenv; then
    echo -e "${GREEN}Audit backlog limit has been successfully configured in GRUB environment. Compliant Line 70.${NC}"
    compliance_count=$((compliance_count + 1))
  else
    echo -e "${RED}Failed to configure audit backlog limit in GRUB environment. Still Non-Compliant Line 70.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
  fi
fi



echo " Level 71"

echo "Checking data retention for auditd..."
if grep -q "^max_log_file = 50" /etc/audit/auditd.conf && grep -q "^max_log_file_action = keep_logs" /etc/audit/auditd.conf; then
  # If data retention settings are correct, print compliance message
  echo -e "${GREEN}Auditd data retention settings are configured correctly. Compliant Line 71.${NC}"
  compliance_count=$((compliance_count + 1))
else
  # If data retention settings are not correct, print non-compliance message
  echo -e "${RED}Auditd data retention settings are not configured correctly. Non-Compliant Line 71.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
  
  # Suggest remediation
  echo "Remediating the data retention settings..."
  
  # Update the auditd configuration
  sudo sed -i 's/^max_log_file.*/max_log_file = 50/' /etc/audit/auditd.conf
  sudo sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
  
  # Restart auditd service to apply changes
  sudo systemctl restart auditd
  
  # Verify if the changes were successfully applied
  if grep -q "^max_log_file = 50" /etc/audit/auditd.conf && grep -q "^max_log_file_action = keep_logs" /etc/audit/auditd.conf; then
    echo -e "${GREEN}Auditd data retention settings have been successfully updated. Compliant Line 71.${NC}"
    compliance_count=$((compliance_count + 1))
  else
    echo -e "${RED}Failed to update auditd data retention settings. Still Non-Compliant Line 71.${NC}"
    non_compliance_count=$((non_compliance_count + 1))
  fi
fi


echo " Level 72"

echo "Checking configuration for audit log storage size"

# Define the maximum log file size (in MB) based on site policy
LOG_FILE_SIZE=100

# Set the max_log_file in auditd configuration
if grep -q "max_log_file" /etc/audit/auditd.conf; then
  sed -i "s/^max_log_file.*/max_log_file = $LOG_FILE_SIZE/" /etc/audit/auditd.conf
else
  echo "max_log_file = $LOG_FILE_SIZE" >> /etc/audit/auditd.conf
fi

# Verify the setting
if grep -q "max_log_file = $LOG_FILE_SIZE" /etc/audit/auditd.conf; then
  echo -e "${GREEN}Audit log file size set to $LOG_FILE_SIZE MB. Compliant Line 72.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}Failed to configure audit log file size. Please check manually. Non-Compliant Line 72.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
fi

echo " Level 73"

echo "Checking if audit logs are not automatically deleted"

# Set max_log_file_action to keep_logs
if grep -q "max_log_file_action" /etc/audit/auditd.conf; then
  sed -i "s/^max_log_file_action.*/max_log_file_action = keep_logs/" /etc/audit/auditd.conf
else
  echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf
fi

# Verify the setting
if grep -q "max_log_file_action = keep_logs" /etc/audit/auditd.conf; then
  echo -e "${GREEN}Audit logs will not be automatically deleted (keep_logs). Compliant Line 73.${NC}"
  compliance_count=$((compliance_count + 1))
else
  echo -e "${RED}Failed to configure audit log deletion policy. Please check manually. Non-Compliant Line 73.${NC}"
  non_compliance_count=$((non_compliance_count + 1))
fi

echo " Level 74"

echo "checking system halt when audit logs are full..."

# Set space_left_action, action_mail_acct, and admin_space_left_action in the auditd configuration

# Uncomment these lines to apply the changes
sed -i '/^space_left_action/d' /etc/audit/auditd.conf
sed -i '/^action_mail_acct/d' /etc/audit/auditd.conf
sed -i '/^admin_space_left_action/d' /etc/audit/auditd.conf
echo "space_left_action = email" >> /etc/audit/auditd.conf
echo "action_mail_acct = root" >> /etc/audit/auditd.conf
echo "admin_space_left_action = halt" >> /etc/audit/auditd.conf

# Verify that the settings have been applied
if grep -q "space_left_action = email" /etc/audit/auditd.conf && \
   grep -q "action_mail_acct = root" /etc/audit/auditd.conf && \
   grep -q "admin_space_left_action = halt" /etc/audit/auditd.conf; then
  echo -e "${GREEN}System will halt when audit logs are full. Compliant Line 74.${NC}"
else
  echo -e "${RED}Failed to configure system halt for full audit logs. Non-Compliant Line 74. Please check manually.${NC}"
fi

echo " Level 75"

# Check if logging to a remote server is configured
if grep -q '\*\.\* @@' /etc/rsyslog.conf; then
  echo -e "${GREEN}Logging to a remote server is configured in rsyslog. Compliant Line 75.${NC}"
else
  echo -e "${RED}Logging to a remote server is not configured in rsyslog. Non-Compliant Line 75.${NC}"

  # Remediation: Configure remote logging in rsyslog
  echo "Configuring logging to a remote server in rsyslog..."
  
  # Adding a line to configure logging to a remote server (replace 'logserver.example.com' with the actual remote server)
  sudo bash -c 'echo "*.* @@logserver.example.com:514" >> /etc/rsyslog.conf'
  
  # Restart rsyslog to apply the changes
  sudo systemctl restart rsyslog
  
  # Verify if logging to a remote server is now configured
  if grep -q '\*\.\* @@' /etc/rsyslog.conf; then
    echo -e "${GREEN}Logging to a remote server has been successfully configured. Compliant Line 75.${NC}"
  else
    echo -e "${RED}Failed to configure logging to a remote server. Still Non-Compliant Line 75.${NC}"
  fi
fi

# Check if encryption is enabled for logs in rsyslog
if grep -q '\$ActionSendStreamDriver gtls' /etc/rsyslog.conf; then
  echo -e "${GREEN}Log encryption is enabled in rsyslog. Compliant Line 75.${NC}"
else
  echo -e "${RED}Log encryption is not enabled in rsyslog. Non-Compliant Line 75.${NC}"

  # Remediation: Enable encryption for logs in rsyslog
  echo "Enabling encryption for logs in rsyslog..."

  # Adding necessary lines to enable TLS encryption (replace 'logserver.example.com' with the actual server and certificate paths)
  sudo bash -c 'cat << EOF >> /etc/rsyslog.conf
# Enable TLS for secure communication
\$DefaultNetstreamDriverCAFile /etc/ssl/certs/ca-certificates.crt
\$ActionSendStreamDriver gtls
\$ActionSendStreamDriverMode 1
\$ActionSendStreamDriverAuthMode x509/name
\$ActionSendStreamDriverPermittedPeer logserver.example.com
EOF'
  
  # Restart rsyslog to apply the changes
  sudo systemctl restart rsyslog

  # Verify if encryption is now enabled
  if grep -q '\$ActionSendStreamDriver gtls' /etc/rsyslog.conf; then
    echo -e "${GREEN}Log encryption has been successfully enabled in rsyslog. Compliant Line 75.${NC}"
  else
    echo -e "${RED}Failed to enable log encryption in rsyslog. Still Non-Compliant Line 75.${NC}"
  fi
fi


echo " Level 76"

# Check rsyslog installation and configuration
echo "Checking rsyslog configuration..."

# Check if rsyslog is installed
if ! command -v rsyslogd &> /dev/null; then
  echo -e "${RED}rsyslog is not installed. Non-Compliant Line 76.${NC}"
  
  # Remediation: Install rsyslog
  echo "Installing rsyslog..."
  sudo yum install -y rsyslog

  # Verify if rsyslog installation was successful
  if command -v rsyslogd &> /dev/null; then
    echo -e "${GREEN}rsyslog has been successfully installed. Compliant Line 76.${NC}"
  else
    echo -e "${RED}Failed to install rsyslog. Still Non-Compliant Line 76.${NC}"
  fi
else
  echo -e "${GREEN}rsyslog is installed. Compliant Line 76.${NC}"
fi

# Check if TCP logging is enabled in rsyslog
if grep -q '^$ModLoad imtcp' /etc/rsyslog.conf && grep -q '^$InputTCPServerRun 514' /etc/rsyslog.conf; then
  echo -e "${GREEN}TCP logging is enabled in rsyslog. Compliant Line 76.${NC}"
else
  echo -e "${RED}TCP logging is not enabled in rsyslog. Non-Compliant Line 76.${NC}"
  
  # Remediation: Enable TCP logging in rsyslog
  echo "Enabling TCP logging in rsyslog configuration..."
  
  # Ensure the necessary modules and configurations are set for TCP logging
  sudo sed -i '/^#\$ModLoad imtcp/s/^#//' /etc/rsyslog.conf
  sudo sed -i '/^#\$InputTCPServerRun 514/s/^#//' /etc/rsyslog.conf
  
  # Restart rsyslog to apply changes
  sudo systemctl restart rsyslog

  # Verify if TCP logging is now enabled
  if grep -q '^$ModLoad imtcp' /etc/rsyslog.conf && grep -q '^$InputTCPServerRun 514' /etc/rsyslog.conf; then
    echo -e "${GREEN}TCP logging has been successfully enabled in rsyslog. Compliant Line 76.${NC}"
  else
    echo -e "${RED}Failed to enable TCP logging in rsyslog. Still Non-Compliant Line 76.${NC}"
  fi
fi


echo " Level 77"

# Check systemd-journald configuration
echo "Checking systemd-journald configuration..."

# Check if journald is configured for persistent storage
if grep -q '^Storage=persistent' /etc/systemd/journald.conf; then
  echo -e "${GREEN}systemd-journald is configured for persistent logging. Compliant Line 77.${NC}"
else
  echo -e "${RED}systemd-journald is not configured for persistent logging. Non-Compliant Line 77.${NC}"
  
  # Remediation: Set journald to persistent storage
  echo "Configuring journald for persistent logging..."
  sudo sed -i 's/^#Storage=auto/Storage=persistent/' /etc/systemd/journald.conf
  
  # Restart systemd-journald to apply changes
  sudo systemctl restart systemd-journald
  
  # Verify if the configuration is updated
  if grep -q '^Storage=persistent' /etc/systemd/journald.conf; then
    echo -e "${GREEN}systemd-journald has been successfully configured for persistent logging. Compliant Line 77.${NC}"
  else
    echo -e "${RED}Failed to configure persistent logging for systemd-journald. Still Non-Compliant Line 77.${NC}"
  fi
fi

# Check if a max log file size is set in systemd-journald
if grep -q '^SystemMaxUse=' /etc/systemd/journald.conf; then
  echo -e "${GREEN}A maximum log file size is set in journald configuration. Compliant Line 77.${NC}"
else
  echo -e "${RED}No maximum log file size is set in journald configuration. Non-Compliant Line 77.${NC}"
  
  # Remediation: Set a maximum log file size
  echo "Setting a maximum log file size in journald configuration..."
  sudo sed -i '/\[Journal\]/a SystemMaxUse=500M' /etc/systemd/journald.conf
  
  # Restart systemd-journald to apply changes
  sudo systemctl restart systemd-journald
  
  # Verify if the max log file size is now set
  if grep -q '^SystemMaxUse=' /etc/systemd/journald.conf; then
    echo -e "${GREEN}A maximum log file size has been successfully set in journald configuration. Compliant Line 77.${NC}"
  else
    echo -e "${RED}Failed to set a maximum log file size in journald configuration. Still Non-Compliant Line 77.${NC}"
  fi
fi



# echo " Level 78"

# # Commented out update function for SSH configuration
# update_ssh_config() {
#     PARAM=$1
#     VALUE=$2
#     CONFIG_FILE="/etc/ssh/sshd_config"

#     # Check if the parameter exists in the file and update it if necessary
#     if grep -q "^${PARAM}" $CONFIG_FILE; then
#         sed -i "s/^${PARAM}.*/${PARAM} ${VALUE}/" $CONFIG_FILE
#     else
#         echo "${PARAM} ${VALUE}" >> $CONFIG_FILE
#     fi
# }

# echo " Level 81"

# # 15. Ensure SSH X11 forwarding is disabled
# echo "Checking SSH X11 forwarding configuration..."
# if grep -q "^X11Forwarding no" /etc/ssh/sshd_config; then
#     echo -e "${GREEN}X11 forwarding is disabled. Compliant Line 81.${NC}"
# else
#     echo -e "${RED}X11 forwarding is enabled. Manual intervention needed Non-Compliant Line 81.${NC}"
#     # Uncomment to remediate:
#     update_ssh_config "X11Forwarding" "no"
#     systemctl restart sshd
# fi

# echo " Level 82"

# # 16. Ensure SSH AllowTcpForwarding is disabled
# echo "Checking SSH AllowTcpForwarding configuration..."
# if grep -q "^AllowTcpForwarding no" /etc/ssh/sshd_config; then
#     echo -e "${GREEN}SSH AllowTcpForwarding is disabled. Compliant Line 82.${NC}"
# else
#     echo -e "${RED}SSH AllowTcpForwarding is enabled. Manual intervention needed Non-Compliant Line 82.${NC}"
#     # Uncomment to remediate:
#     update_ssh_config "AllowTcpForwarding" "no"
#     systemctl restart sshd
# fi

echo " Level 83"

echo "Checking authselect configuration..."

# Check if authselect is installed
if ! command -v authselect &> /dev/null; then
  echo -e "${RED}authselect is not installed. Non-Compliant Line 83.${NC}"
  
  # Remediation: Install authselect
  echo "Installing authselect..."
  sudo yum install -y authselect
  
  # Verify if installation was successful
  if command -v authselect &> /dev/null; then
    echo -e "${GREEN}authselect has been successfully installed. Compliant Line 83.${NC}"
  else
    echo -e "${RED}Failed to install authselect. Still non-compliant.${NC}"
  fi

else
  echo -e "${GREEN}authselect is installed. Compliant Line 83.${NC}"

  # Check the current authselect profile
  authselect_status=$(authselect current | grep Profile)
  if [ -n "$authselect_status" ]; then
    echo -e "${GREEN}Authselect profile in use: $authselect_status. Compliant Line 83.${NC}"
  else
    echo -e "${RED}No authselect profile is currently in use. Non-Compliant Line 83.${NC}"
    
    # Remediation: Set a default authselect profile
    echo "Setting a default authselect profile..."
    sudo authselect select sssd --force

    # Verify if the profile was successfully set
    authselect_status=$(authselect current | grep Profile)
    if [ -n "$authselect_status" ]; then
      echo -e "${GREEN}Authselect profile has been successfully set. Compliant Line 83.${NC}"
    else
      echo -e "${RED}Failed to set authselect profile. Still non-compliant.${NC}"
    fi
  fi
fi


echo " Level 84"

echo "Checking PAM configuration..."

# Check if the necessary PAM files are in place
pam_files=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth" "/etc/pam.d/sshd" "/etc/pam.d/login")

for file in "${pam_files[@]}"
do
  if [ -f "$file" ]; then
    echo -e "${GREEN}$file exists. Compliant Line 84.${NC}"
  else
    echo -e "${RED}$file does not exist. Non-Compliant Line 84.${NC}"
  fi
done

echo " Level 85"

echo "Checking PAM and Login Settings..."

# 1. Check pam_unix.so in /etc/pam.d/password-auth
echo "Checking pam_unix.so in /etc/pam.d/password-auth..."
pam_unix_auth=$(egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth)
if [[ "$pam_unix_auth" == *"remember=18"* ]]; then
  echo -e "${GREEN}pam_unix.so has 'remember=18' configured correctly. Compliant Line 85.${NC}"
else
  echo -e "${RED}pam_unix.so does not have 'remember=18' configured. Non-Compliant Line 85.${NC}"
fi

# 2. Check pam_pwhistory.so in /etc/pam.d/password-auth
echo "Checking pam_pwhistory.so in /etc/pam.d/password-auth..."
pam_pwhistory_auth=$(egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/password-auth)
if [[ "$pam_pwhistory_auth" == *"remember=18"* ]]; then
  echo -e "${GREEN}pam_pwhistory.so has 'remember=18' configured correctly in password-auth. Compliant Line 85.${NC}"
else
  echo -e "${RED}pam_pwhistory.so does not have 'remember=18' configured in password-auth. Non-Compliant Line 85.${NC}"
fi

# 3. Check pam_pwhistory.so in /etc/pam.d/system-auth
echo "Checking pam_pwhistory.so in /etc/pam.d/system-auth..."
pam_pwhistory_system=$(egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/system-auth)
if [[ "$pam_pwhistory_system" == *"remember=18"* ]]; then
  echo -e "${GREEN}pam_pwhistory.so has 'remember=18' configured correctly in system-auth. Compliant Line 85.${NC}"
else
  echo -e "${RED}pam_pwhistory.so does not have 'remember=18' configured in system-auth. Non-Compliant Line 85.${NC}"
fi

# 4. Check PASS_WARN_AGE in /etc/login.defs
echo "Checking PASS_WARN_AGE in /etc/login.defs..."
pass_warn_age=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')
 
# Ensure the value is valid before comparison
if [ -z "$pass_warn_age" ]; then
  echo -e "${RED}PASS_WARN_AGE is not set in /etc/login.defs. Non-Compliant Line 85 .${NC}"
else
  # Compare PASS_WARN_AGE only if it's a number
  if [ "$pass_warn_age" -ge 7 ] 2>/dev/null; then
    echo -e "${GREEN}PASS_WARN_AGE is set to $pass_warn_age (>= 7 is compliant). Compliant Line 85 .${NC}"
  else
    echo -e "${RED}PASS_WARN_AGE is set to $pass_warn_age (< 7 is not compliant). Non-Compliant Line 85 .${NC}"
  fi
fi

# 5. Check INACTIVE setting for user accounts
echo "Checking INACTIVE setting for user accounts..."
inactive_days=$(useradd -D | grep INACTIVE | cut -d= -f2)
if [ "$inactive_days" -le 30 ]; then
  echo -e "${GREEN}INACTIVE account lockout is set to $inactive_days days (<= 30 is compliant). Compliant Line 85.${NC}"
else
  echo -e "${RED}INACTIVE account lockout is set to $inactive_days days (> 30 is not compliant). Non-Compliant Line 85.${NC}"
fi

echo "PAM and Login Settings Check Completed."








