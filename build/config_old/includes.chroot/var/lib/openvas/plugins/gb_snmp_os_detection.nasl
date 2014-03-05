###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_snmp_os_detection.nasl 44 2013-11-04 19:58:48Z jan $
#
# SNMP OS Identification
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This script performs SNMP based OS detection.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103429";   

if (description)
{
 
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2012-02-17 10:17:12 +0100 (Fri, 17 Feb 2012)");
 script_name("SNMP OS Identification");
 desc = "
 Summary:
 " + tag_summary; script_description(desc);
 script_summary("Detects remote operating system version from SNMP sysDesc");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_snmp_sysdesc.nasl");
 script_require_udp_ports("Services/snmp", 161);
 script_require_keys("SNMP/sysdesc");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

SCRIPT_DESC = "SNMP OS Identification";

include("host_details.inc");

sysdesc = get_kb_item("SNMP/sysdesc");
if(!sysdesc)exit(0);

# Linux SOA1000 2.6.26.8 #62 SMP Mon Sep 21 18:13:37 CST 2009 i686 unknown
if(sysdesc =~ "^Linux") {

  set_kb_item(name:"Host/OS/SNMP", value:"Linux");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"Linux [^ ]* ([0-3]+\.[^ ]*).*",string:sysdesc);

  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:linux:kernel:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"Linux " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  } else {
    register_host_detail(name:"OS", value:"cpe:/o:linux:kernel", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"Linux", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);  

}  

# SINDOH MF 3300_2300 version NR.APS.N434 kernel 2.6.18.5 All-N-1 
if(sysdesc =~ "kernel [0-3]\.") {

   set_kb_item(name:"Host/OS/SNMP", value:"Linux");
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

   version = eregmatch(pattern:"kernel ([0-3]+\.[^ ]*).*",string:sysdesc);

   if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:linux:kernel:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"Linux" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  } else {
    register_host_detail(name:"OS", value:"cpe:/o:linux:kernel", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"Linux", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

} 

# Microsoft Corp. Windows 98. 
# Hardware: x86 Family 15 Model 4 Stepping 1 AT/AT COMPATIBLE - Software: Windows 2000 Version 5.1 (Build 2600 Uniprocessor Free) 
# Hardware: x86 Family 6 Model 8 Stepping 3 AT/AT COMPATIBLE - Software: Windows NT Version 4.0 (Build Number: 1381 Uniprocessor Free ) 
if(sysdesc =~ "Microsoft Corp. Windows 98" || sysdesc =~ "Hardware:.*Software: Windows") {

   set_kb_item(name:"Host/OS/SNMP", value:"Windows");
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:75);

   if("windows 98" >< sysdesc) {
     register_host_detail(name:"OS", value:"cpe:/o:microsoft:windows_98", nvt:SCRIPT_OID, desc:SCRIPT_DESC);
     register_host_detail(name:"OS", value:"Windows 98", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
     exit(0);
   }

   version = eregmatch(pattern:"Software: Windows.*Version ([0-9.]+)",string:sysdesc);

   if(isnull(version[1]) || version[1] !~ "[4-6]\.[0-2]") { 
     register_host_detail(name:"OS", value:"cpe:/o:microsoft:windows", nvt:SCRIPT_OID, desc:SCRIPT_DESC);
     register_host_detail(name:"OS", value:"Windows", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
     exit(0);
   }

   winVal = version[1];

   if(winVal == "4.0") {
     register_host_detail(name:"OS", value:"cpe:/o:microsoft:windows_nt:4.0", nvt:SCRIPT_OID, desc:SCRIPT_DESC);
     register_host_detail(name:"OS", value:"Windows NT", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
     exit(0);
   }

   if((winVal == "5.0" || winVal == "5.1") && ("Windows 2000" >< sysdesc)) {
     register_host_detail(name:"OS", value:"cpe:/o:microsoft:windows_2000", nvt:SCRIPT_OID, desc:SCRIPT_DESC);
     register_host_detail(name:"OS", value:"Windows 2000", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
     exit(0);
   }
 
   if(winVal == "5.1") {
     register_host_detail(name:"OS", value:"cpe:/o:microsoft:windows_xp", nvt:SCRIPT_OID, desc:SCRIPT_DESC);
     register_host_detail(name:"OS", value:"Windows XP", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
     exit(0);
   }

   if(winVal == "5.2") {
     register_host_detail(name:"OS", value:"cpe:/o:microsoft:windows_server_2003", nvt:SCRIPT_OID, desc:SCRIPT_DESC);
     register_host_detail(name:"OS", value:"Windows Server 2003", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
     exit(0);
   }

   if(winVal == "6.0") {
     register_host_detail(name:"OS", value:"cpe:/o:microsoft:windows_vista", nvt:SCRIPT_OID, desc:SCRIPT_DESC);
     register_host_detail(name:"OS", value:"Windows Vista", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
     exit(0);
   }

   if(winVal == "6.1") {
     register_host_detail(name:"OS", value:"cpe:/o:microsoft:windows_7", nvt:SCRIPT_OID, desc:SCRIPT_DESC);
     register_host_detail(name:"OS", value:"Windows 7", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
     exit(0);
   } 

   if(winVal == "6.2") {
     register_host_detail(name:"OS", value:"cpe:/o:microsoft:windows_8", nvt:SCRIPT_OID, desc:SCRIPT_DESC);
     register_host_detail(name:"OS", value:"Windows 8", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
   }

   # we dont't know the real windows version if we reached here. So just register windows.
   register_host_detail(name:"OS", value:"cpe:/o:microsoft:windows", nvt:SCRIPT_OID, desc:SCRIPT_DESC);
   register_host_detail(name:"OS", value:"Windows", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
   exit(0);

} 

# FreeBSD infoware-nt.infoware.local 4.11-RELEASE-p26 FreeBSD 4.11-RELEASE-p26 #12: S i386 
if(sysdesc =~ "FreeBSD.* FreeBSD") {

  set_kb_item(name:"Host/OS/SNMP", value:"FreeBSD");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:".*FreeBSD ([0-9.]+[^ ]*).*",string:sysdesc);
  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:freebsd:freebsd:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"FreeBSD " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:freebsd:freebsd", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"FreeBSD", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  

  exit(0);

}  

# NetBSD IPr.archway.net 1.6.1_STABLE NetBSD 1.6.1_STABLE (SCZ_16) #0: Thu May 24 14:42:04 CEST 2007...
if(sysdesc =~ "NetBSD.* NetBSD") {

  set_kb_item(name:"Host/OS/SNMP", value:"NetBSD");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:".*NetBSD ([0-9.]+[^ ]*).*",string:sysdesc);
  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:netbsd:netbsd:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"NetBSD " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:netbsd:netbsd", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"NetBSD", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

}

# Powered by OpenBSD
# OpenBSD frsrvfwbk.dev.netgem.com 4.2 GENERIC#375 i386 
if(sysdesc =~ "^OpenBSD" || sysdesc =~ "Powered by OpenBSD") {

  set_kb_item(name:"Host/OS/SNMP", value:"OpenBSD");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"OpenBSD.* ([0-9.]+) GENERIC",string:sysdesc);

  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:openbsd:openbsd:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"OpenBSD " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:openbsd:openbsd", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"OpenBSD", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

}

# HP-UX rx2600 B.11.23 U ia64 3979036319 
if(sysdesc =~ "^HP-UX") {

  set_kb_item(name:"Host/OS/SNMP", value:"HP UX");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"^HP-UX [^ ]* ([^ ]*)",string:sysdesc);

  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:hp:hp-ux:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"HP UX " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:hp:hp-ux", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"HP UX", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

}

# SunOS NXSAM 5.10 Generic_127128-11 i86pc 
# SunOS wlanapp 5.10 Generic_139555-08 sun4v 
if(sysdesc =~ "^SunOS") {

  typ = " (sparc)";
  if("i86pc" >< sysdesc) {
    typ = " (i386)";
  } 

  set_kb_item(name:"Host/OS/SNMP", value:"Sun Solaris" + typ);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"^SunOS .* (5\.[0-9]+)", string:sysdesc);

  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:sun:sunos:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"SunOS " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:sun:sunos", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"SunOS", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

}

# HP ETHERNET MULTI-ENVIRONMENT,ROM P.22.01,JETDIRECT,JD86,EEPROM P.24.07,CIDATE 12/13/2002 
if("JETDIRECT" >< sysdesc) {

  set_kb_item(name:"Host/OS/SNMP", value:"HP JetDirect");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  register_host_detail(name:"OS", value:"cpe:/h:hp:jetdirect", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  register_host_detail(name:"OS", value:"JetDirect", nvt:SCRIPT_OID,desc:SCRIPT_DESC);

  exit(0);

}

# Cisco Internetwork Operating System Software  IOS (tm) GS Software (GSR-P-M), Version 12.0(21)ST7, EARLY DEPLOYMENT RELEASE SOFTWARE (fc1)  ...
# Cisco IOS Software, C3550 Software (C3550-IPSERVICESK9-M), Version 12.2(25)SEE2, RELEASE SOFTWARE (fc1)  
if(sysdesc =~ "^Cisco IOS" || "IOS (tm)" >< sysdesc) {

  set_kb_item(name:"Host/OS/SNMP", value:"Cisco IOS");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"IOS.*Version ([0-9]*\.[0-9]*\([0-9a-zA-Z]+\)[A-Z0-9.]*),", string:sysdesc);

  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:cisco:ios:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"IOS " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:cisco:ios", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"IOS", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

}

# Base Operating System Runtime AIX version: 05.03.0000.0060
if("Base Operating System Runtime AIX" >< sysdesc) {

  set_kb_item(name:"Host/OS/SNMP", value:"AIX");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"Base Operating System Runtime AIX version: ([0-9.]+)", string:sysdesc);

  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:ibm:aix:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"AIX " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:ibm:aix", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"AIX", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

}
# Darwin mars.imageline.it 9.6.0 Darwin Kernel Version 9.6.0: Mon Nov 24 17:37:00 PST 2008; root:xnu-1228.9.59~1/RELEASE_I386 i386 
if("Darwin Kernel" >< sysdesc) {

  set_kb_item(name:"Host/OS/SNMP", value:"Apple Mac OS X");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  register_host_detail(name:"OS", value:"cpe:/o:apple:mac_os_x", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  register_host_detail(name:"OS", value:"MAC OS X", nvt:SCRIPT_OID,desc:SCRIPT_DESC);

  exit(0);

} 

# Juniper Networks, Inc. ex3200-24t internet router, kernel JUNOS 10.1R1.8 #0: 2010-02-12 17:24:20 UTC 
if("Juniper Networks" >< sysdesc && "JUNOS" >< sysdesc) {

  set_kb_item(name:"Host/OS/SNMP", value:"JUNOS");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"JUNOS ([^ ]+)", string:sysdesc);

  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:juniper:junos:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"JunOS " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:juniper:junos", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"JunOs", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

}

# tuneld.slrsuzbar.com AlphaServer 1200 5/533 4MB OpenVMS V7.3-1 Compaq TCP/IP Services for OpenVMS
if("OpenVMS" >< sysdesc) {

  set_kb_item(name:"Host/OS/SNMP", value:"OpenVMS");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"OpenVMS V([^ ]+)", string:sysdesc);

  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:hp:openvms:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"OpenVMS " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:hp:openvms", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"OpenVMS", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

}

# Novell NetWare 5.70.08  October 3, 2008
if("Novell NetWare" >< sysdesc) {

  set_kb_item(name:"Host/OS/SNMP", value:"Novell NetWare");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"Novell NetWare ([0-9.]+)", string:sysdesc);

  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:novell:netware:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"Netware " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:novell:netware", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"Netware", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

}

# Silicon Graphics Octane2 running IRIX64 version 6.5 
# Silicon Graphics O2 running IRIX version 6.5 
if(sysdesc =~ "running IRIX(64)? version") {
 
  set_kb_item(name:"Host/OS/SNMP", value:"IRIX");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"version ([0-9.]+)",string:sysdesc);

  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:sgi:irix:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"IRIX " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:sgi:irix", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"IRIX", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

}

# SCO OpenServer Release 6 
if("SCO OpenServer" >< sysdesc) {

  set_kb_item(name:"Host/OS/SNMP", value:"SCO OpenServer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"SCO OpenServer Release ([0-9]+)", string:sysdesc);

  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:sco:openserver:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"SCO " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:sco:openserver", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"SCO", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

}

# SCO UnixWare 7.1.4 
if("SCO UnixWare" >< sysdesc) {

  set_kb_item(name:"Host/OS/SNMP", value:"SCO UnixWare");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"SCO UnixWare ([0-9.]+)", string:sysdesc);

  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:sco:unixware:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"Unixware " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:sco:unixware", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"Unixware", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

}

# Novell UnixWare v2.1 
if("Novell UnixWare" >< sysdesc) {

  set_kb_item(name:"Host/OS/SNMP", value:"Novell UnixWare");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"Novell UnixWare v([0-9.]+)", string:sysdesc);

  if(!isnull(version[1])) {
    register_host_detail(name:"OS", value:"cpe:/o:novell:unixware:" + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"UnixWare " + version[1], nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }  else {
    register_host_detail(name:"OS", value:"cpe:/o:novell:unixware", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
    register_host_detail(name:"OS", value:"UnixWare", nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  }

  exit(0);

}


