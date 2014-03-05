#
#VID dc8c08c7-1e7c-11db-88cf-000c6ec775d9
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from vuxml or freebsd advisories
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_insight = "The following packages are affected:
   apache
   apache+mod_perl
   apache+ipv6
   apache_fp
   ru-apache
   ru-apache+mod_ssl
   apache+ssl
   apache+mod_ssl
   apache+mod_ssl+ipv6
   apache+mod_ssl+mod_accel
   apache+mod_ssl+mod_accel+ipv6
   apache+mod_ssl+mod_accel+mod_deflate
   apache+mod_ssl+mod_accel+mod_deflate+ipv6
   apache+mod_ssl+mod_deflate
   apache+mod_ssl+mod_deflate+ipv6
   apache+mod_ssl+mod_snmp
   apache+mod_ssl+mod_snmp+mod_accel
   apache+mod_ssl+mod_snmp+mod_accel+ipv6
   apache+mod_ssl+mod_snmp+mod_deflate
   apache+mod_ssl+mod_snmp+mod_deflate+ipv6
   apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://marc.theaimsgroup.com/?l=apache-httpd-announce&m=115409818602955
http://www.vuxml.org/freebsd/dc8c08c7-1e7c-11db-88cf-000c6ec775d9.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(57145);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2006-3747");
 script_tag(name:"cvss_base", value:"7.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: apache");


 script_description(desc);

 script_summary("FreeBSD Ports: apache");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"apache");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36_1")<0) {
    txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0.46")>=0 && revcomp(a:bver, b:"2.0.58_2")<0) {
    txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.2.0")>=0 && revcomp(a:bver, b:"2.2.2_1")<0) {
    txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_perl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36_1")<0) {
    txt += 'Package apache+mod_perl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.37")<0) {
    txt += 'Package apache+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache_fp");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package apache_fp version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ru-apache");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package ru-apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ru-apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package ru-apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.34.1.57_2")<0) {
    txt += 'Package apache+ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_accel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_accel+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_accel+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_accel+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_accel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_accel+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
