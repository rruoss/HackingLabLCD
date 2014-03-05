#
#VID ad74a1bd-16d2-11d9-bc4a-000c41e2cdad
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
   mod_php4-twig, php4-cgi, php4-cli, php4-dtc, php4-horde,
   php4-nms, php4, mod_php, mod_php4, php5, php5-cgi,
   php5-cli, mod_php5

The installed version of PHP suffers from a vulnerability
that allows remote attackers to read sensitive memory
contents.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://marc.theaimsgroup.com/?l=bugtraq&m=109527531130492
http://www.vuxml.org/freebsd/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html";
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
 script_id(52359);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(11334);
 script_cve_id("CVE-2004-0958");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("php -- php_variables memory disclosure");


 script_description(desc);

 script_summary("php -- php_variables memory disclosure");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"mod_php4-twig");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
    txt += 'Package mod_php4-twig version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-cgi");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
    txt += 'Package php4-cgi version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-cli");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
    txt += 'Package php4-cli version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-dtc");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
    txt += 'Package php4-dtc version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-horde");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
    txt += 'Package php4-horde version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-nms");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
    txt += 'Package php4-nms version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
    txt += 'Package php4 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_php");
if(!isnull(bver) && revcomp(a:bver, b:"4")>=0 && revcomp(a:bver, b:"4.3.8_2,1")<=0) {
    txt += 'Package mod_php version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_php4");
if(!isnull(bver) && revcomp(a:bver, b:"4")>=0 && revcomp(a:bver, b:"4.3.8_2,1")<=0) {
    txt += 'Package mod_php4 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.1")<=0) {
    txt += 'Package php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-cgi");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.1")<=0) {
    txt += 'Package php5-cgi version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-cli");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.1")<=0) {
    txt += 'Package php5-cli version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.1,1")<=0) {
    txt += 'Package mod_php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_warning(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
