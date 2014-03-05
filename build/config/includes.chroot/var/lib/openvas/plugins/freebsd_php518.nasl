#
#VID bdab0acd-d4cd-11e1-8a1c-14dae9ebcf89
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID bdab0acd-d4cd-11e1-8a1c-14dae9ebcf89
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
   php53
   php52

CVE-2012-2688
Unspecified vulnerability in the _php_stream_scandir function in the
stream implementation in PHP before 5.3.15 and 5.4.x before 5.4.5 has
unknown impact and remote attack vectors, related to an 'overflow.'";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.php.net/archive/2012.php#id2012-07-19-1
http://www.vuxml.org/freebsd/bdab0acd-d4cd-11e1-8a1c-14dae9ebcf89.html";
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
 script_id(71521);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-2688");
 script_tag(name:"risk_factor", value:"Critical");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
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
if(!isnull(bver) && revcomp(a:bver, b:"5.4")>0 && revcomp(a:bver, b:"5.4.5")<0) {
    txt += "Package php5 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"php53");
if(!isnull(bver) && revcomp(a:bver, b:"5.3.15")<0) {
    txt += "Package php53 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"php52");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.17_10")<=0) {
    txt += "Package php52 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt + "\n" + desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
