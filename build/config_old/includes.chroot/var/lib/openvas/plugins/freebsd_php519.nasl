#
#VID 918f38cd-f71e-11e1-8bd8-0022156e8794
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 918f38cd-f71e-11e1-8bd8-0022156e8794
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
   php5
   php52
   php53

CVE-2011-1398
The sapi_header_op function in main/SAPI.c in PHP before 5.3.11 does
not properly handle %0D sequences (aka carriage return characters),
which allows remote attackers to bypass an HTTP response-splitting
protection mechanism via a crafted URL, related to improper
interaction between the PHP header function and certain browsers, as
demonstrated by Internet Explorer and Google Chrome.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://bugs.php.net/bug.php?id=60227
http://www.vuxml.org/freebsd/918f38cd-f71e-11e1-8bd8-0022156e8794.html";
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
 script_id(71867);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2011-1398");
 script_tag(name:"risk_factor", value:"Medium");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-09-07 11:47:17 -0400 (Fri, 07 Sep 2012)");
 script_name("FreeBSD Ports: php5");

 script_description(desc);

 script_summary("FreeBSD Ports: php5");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
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
vuln = 0;
txt = "";
bver = portver(pkg:"php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.2")>=0 && revcomp(a:bver, b:"5.3.11")<0) {
    txt += "Package php5 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"5.4")>=0 && revcomp(a:bver, b:"5.4.1")<0) {
    txt += "Package php5 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"php52");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += "Package php52 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"php53");
if(!isnull(bver) && revcomp(a:bver, b:"5.3.11")<0) {
    txt += "Package php53 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt + "\n" + desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
