#!/bin/bash

echo "creation of /opt/vmware directories"
rm -rf /opt/vmware
mkdir -p /opt/vmware
mkdir -p /opt/vmware/config
mkdir -p /opt/vmware/software
mkdir -p /opt/vmware/scripts
mkdir -p /mnt/images-ro
#mkdir -p /mnt/images-rw

export http_proxy=http://buster.csnc.ch:48080
apt-get -y install cifs-utils

export PASSWD=""
echo "mounting images-ro from merlin4"
mount -t cifs //merlin4.csnc.ch/vmware/images-ro /mnt/images-ro -o iocharset=utf8,uid=0,file_mode=0600,dir_mode=0600
#echo "mounting images-rw from merlin4"
#mount -t cifs //merlin4.csnc.ch/vmware/images-rw /mnt/images-rw -o iocharset=utf8,uid=0,file_mode=0600,dir_mode=0600

echo "directory listing /mnt/"
ls -al /mnt

echo "start syncing from merlin4 to localhost /opt/vmware/"
echo "syncing /opt/vmware/config"
rsync -rv /mnt/images-ro/config/ /opt/vmware/config
echo "syncing /opt/vmware/scripts"
rsync -rv /mnt/images-ro/scripts/ /opt/vmware/scripts
echo "syncing /opt/vmware/software"
rsync -rv /mnt/images-ro/software/ /opt/vmware/software
echo "syncing /opt/vmware/vmware"
livecd_user=`perl -e '($login) = getpwuid(999);print "$login\n";'`
installed_user=`perl -e '($login) = getpwuid(1000);print "$login\n";'`

if [ ! -z $livecd_user ];
then
	echo "LiveCD boot mode (not installed)"
	vmuser=$livecd_user	
fi

if [ ! -z $installed_user ];
then
	echo "LiveCD is installed (installation mode)"
	vmuser=$installed_user
fi



chown -R $vmuser:$vmuser /opt/vmware
cp /opt/vmware/config/user/.vmware/inventory.vmls /home/$vmuser/.vmware/
cp /opt/vmware/config/user/.vmware/preferences /home/$vmuser/.vmware/
cp /opt/vmware/config/user/.vmware/shortcuts /home/$vmuser/.vmware/
chown -R $vmuser:$vmuser /home/$userName/.vmware/

#INSTALLATION VMWARE WORKSTATION9
echo "starting vmware workstation installation"
bash /opt/vmware/software/vmware-workstation/VMware-Workstation-Full-9.0.0-812388.i386.bundle --console

#COPY LICENSE TO THE CORRECT LOCATION
echo "installing license"
cp /opt/vmware/config/etc/vmware/license-ws-90-e1-201202 /etc/vmware/
chmod 644 /etc/vmware/license-ws-90-e1-201202


echo "Syncing Images"
SrcDir=/mnt/images-ro/images
DstDir=/opt/vmware
AvailableMachines=$(ls -l $SrcDir | awk '{print $9}')
TmpFile=/tmp/rsync-selection

for Name in $AvailableMachines
do
        ParamList=("$ParamList $Name - off")
done

dialog --stdout --title "VM Selection" --checklist "Select VMs to Download" 0 0 0 ${ParamList[@]} > $TmpFile

pushd $SrcDir
for VM in $(cat $TmpFile | tr -d \")
do
      echo ----- syncing : $VM
      rsync -rv $VM $DstDir
      chown -R $vmuser:$vmuser $DstDir/$VM
      chmod -R 770 $DstDir/$VM
done
popd

exit



echo "before umounting cifs share"
ls -al /mnt
umount /mnt/images-ro
umount /mnt/images-rw
echo "after umounting cifs share"
ls -al /mnt

echo "================== FINISHED ========================="

