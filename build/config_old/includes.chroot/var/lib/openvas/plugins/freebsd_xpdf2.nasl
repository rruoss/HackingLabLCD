#
#VID 0e43a14d-3f3f-11dc-a79a-0016179b2dd5
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
   xpdf
   zh-xpdf
   ja-xpdf
   ko-xpdf
   kdegraphics
   cups-base
   gpdf
   pdftohtml
   poppler

=====";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.kde.org/info/security/advisory-20070730-1.txt
http://www.vuxml.org/freebsd/0e43a14d-3f3f-11dc-a79a-0016179b2dd5.html";
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
 script_id(58817);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2007-3387");
 script_bugtraq_id(25124);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: xpdf, zh-xpdf, ja-xpdf, ko-xpdf");


 script_description(desc);

 script_summary("FreeBSD Ports: xpdf, zh-xpdf, ja-xpdf, ko-xpdf");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"xpdf");
if(!isnull(bver) && revcomp(a:bver, b:"3.02_2")<0) {
    txt += 'Package xpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"zh-xpdf");
if(!isnull(bver) && revcomp(a:bver, b:"3.02_2")<0) {
    txt += 'Package zh-xpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-xpdf");
if(!isnull(bver) && revcomp(a:bver, b:"3.02_2")<0) {
    txt += 'Package ja-xpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ko-xpdf");
if(!isnull(bver) && revcomp(a:bver, b:"3.02_2")<0) {
    txt += 'Package ko-xpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"kdegraphics");
if(!isnull(bver) && revcomp(a:bver, b:"3.5.7_1")<0) {
    txt += 'Package kdegraphics version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"cups-base");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.11_3")<0) {
    txt += 'Package cups-base version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"gpdf");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package gpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pdftohtml");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package pdftohtml version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"poppler");
if(!isnull(bver) && revcomp(a:bver, b:"0.5.9_4")<0) {
    txt += 'Package poppler version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
