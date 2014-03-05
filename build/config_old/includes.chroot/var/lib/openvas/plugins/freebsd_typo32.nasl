#
#VID 6693bad2-ca50-11de-8ee8-00215c6a37bb
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 6693bad2-ca50-11de-8ee8-00215c6a37bb
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: typo3

CVE-2009-3628
The Backend subcomponent in TYPO3 4.0.13 and earlier, 4.1.x before
4.1.13, 4.2.x before 4.2.10, and 4.3.x before 4.3beta2 allows remote
authenticated users to determine an encryption key via crafted input
to a tt_content form element.

CVE-2009-3629
Multiple cross-site scripting (XSS) vulnerabilities in the Backend
subcomponent in TYPO3 4.0.13 and earlier, 4.1.x before 4.1.13, 4.2.x
before 4.2.10, and 4.3.x before 4.3beta2 allow remote authenticated
users to inject arbitrary web script or HTML via unspecified vectors.

CVE-2009-3630
The Backend subcomponent in TYPO3 4.0.13 and earlier, 4.1.x before
4.1.13, 4.2.x before 4.2.10, and 4.3.x before 4.3beta2 allows remote
authenticated users to place arbitrary web sites in TYPO3 backend
framesets via crafted parameters, related to a 'frame hijacking'
issue.

CVE-2009-3631
The Backend subcomponent in TYPO3 4.0.13 and earlier, 4.1.x before
4.1.13, 4.2.x before 4.2.10, and 4.3.x before 4.3beta2, when the DAM
extension or ftp upload is enabled, allows remote authenticated users
to execute arbitrary commands via shell metacharacters in a filename.

CVE-2009-3632
SQL injection vulnerability in the traditional frontend editing
feature in the Frontend Editing subcomponent in TYPO3 4.0.13 and
earlier, 4.1.x before 4.1.13, 4.2.x before 4.2.10, and 4.3.x before
4.3beta2 allows remote authenticated users to execute arbitrary SQL
commands via unspecified parameters.

CVE-2009-3633
Cross-site scripting (XSS) vulnerability in the
t3lib_div::quoteJSvalue API function in TYPO3 4.0.13 and earlier,
4.1.x before 4.1.13, 4.2.x before 4.2.10, and 4.3.x before 4.3beta2
allows remote attackers to inject arbitrary web script or HTML via
unspecified vectors related to the sanitizing algorithm.

CVE-2009-3634
Cross-site scripting (XSS) vulnerability in the Frontend Login Box
(aka felogin) subcomponent in TYPO3 4.2.0 through 4.2.6 allows remote
attackers to inject arbitrary web script or HTML via unspecified
parameters.

CVE-2009-3635
The Install Tool subcomponent in TYPO3 4.0.13 and earlier, 4.1.x
before 4.1.13, 4.2.x before 4.2.10, and 4.3.x before 4.3beta2 allows
remote attackers to gain access by using only the password's md5 hash
as a credential.

CVE-2009-3636
Cross-site scripting (XSS) vulnerability in the Install Tool
subcomponent in TYPO3 4.0.13 and earlier, 4.1.x before 4.1.13, 4.2.x
before 4.2.10, and 4.3.x before 4.3beta2 allows remote attackers to
inject arbitrary web script or HTML via unspecified parameters.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://typo3.org/teams/security/security-bulletins/typo3-sa-2009-016/
http://secunia.com/advisories/37122/
http://www.vuxml.org/freebsd/6693bad2-ca50-11de-8ee8-00215c6a37bb.html";
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
 script_id(66154);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
 script_cve_id("CVE-2009-3628", "CVE-2009-3629", "CVE-2009-3630", "CVE-2009-3631", "CVE-2009-3632", "CVE-2009-3633", "CVE-2009-3634", "CVE-2009-3635", "CVE-2009-3636");
 script_bugtraq_id(36801);
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("FreeBSD Ports: typo3");


 script_description(desc);

 script_summary("FreeBSD Ports: typo3");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"typo3");
if(!isnull(bver) && revcomp(a:bver, b:"4.2.10")<0) {
    txt += 'Package typo3 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
