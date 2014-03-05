#
#VID 9fff8dc8-7aa7-11da-bf72-00123f589060
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
   apache_fp
   apache+ipv6
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
   apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6

CVE-2005-3352
Cross-site scripting (XSS) vulnerability in the mod_imap module allows
remote attackers to inject arbitrary web script or HTML via the
Referer when using image maps.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.apacheweek.com/features/security-13
http://www.apacheweek.com/features/security-20
http://www.vuxml.org/freebsd/9fff8dc8-7aa7-11da-bf72-00123f589060.html";
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
 script_id(56067);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2005-3352");
 script_bugtraq_id(15834);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
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
if(!isnull(bver) && revcomp(a:bver, b:"1.3")>=0 && revcomp(a:bver, b:"1.3.34_3")<0) {
    txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0.35")>=0 && revcomp(a:bver, b:"2.0.55_2")<0) {
    txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.1")>=0 && revcomp(a:bver, b:"2.1.9_3")<0) {
    txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.2")>=0 && revcomp(a:bver, b:"2.2.0_3")<0) {
    txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_perl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34_1")<0) {
    txt += 'Package apache+mod_perl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache_fp");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package apache_fp version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package apache+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ru-apache");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+30.22_1")<0) {
    txt += 'Package ru-apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ru-apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+30.22+2.8.25_1")<0) {
    txt += 'Package ru-apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.3.33.1.55_2")<0) {
    txt += 'Package apache+ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl+mod_accel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl+mod_accel+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl+mod_accel+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl+mod_accel+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_accel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_accel+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_warning(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
