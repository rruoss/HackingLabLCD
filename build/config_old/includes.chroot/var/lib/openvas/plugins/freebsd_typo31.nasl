#
#VID 653606e9-f6ac-11dd-94d9-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 653606e9-f6ac-11dd-94d9-0030843d3802
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

CVE-2009-0255
The System extension Install tool in TYPO3 4.0.0 through 4.0.9, 4.1.0
through 4.1.7, and 4.2.0 through 4.2.3 creates the encryption key with
an insufficiently random seed, which makes it easier for attackers to
crack the key.

CVE-2009-0256
Session fixation vulnerability in the authentication library in TYPO3
4.0.0 through 4.0.9, 4.1.0 through 4.1.7, and 4.2.0 through 4.2.3
allows remote attackers to hijack web sessions via unspecified vectors
related to (1) frontend and (2) backend authentication.

CVE-2009-0257
Multiple cross-site scripting (XSS) vulnerabilities in TYPO3 4.0.0
through 4.0.9, 4.1.0 through 4.1.7, and 4.2.0 through 4.2.3 allow
remote attackers to inject arbitrary web script or HTML via the (1)
name and (2) content of indexed files to the (a) Indexed Search Engine
(indexed_search) system extension; (b) unspecified test scripts in the
ADOdb system extension; and (c) unspecified vectors in the Workspace
module.

CVE-2009-0258
The Indexed Search Engine (indexed_search) system extension in TYPO3
4.0.0 through 4.0.9, 4.1.0 through 4.1.7, and 4.2.0 through 4.2.3
allows remote attackers to execute arbitrary commands via a crafted
filename containing shell metacharacters, which is not properly
handled by the command-line indexer.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/33617/
http://typo3.org/teams/security/security-bulletins/typo3-sa-2009-001/
http://www.vuxml.org/freebsd/653606e9-f6ac-11dd-94d9-0030843d3802.html";
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
 script_id(63361);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
 script_cve_id("CVE-2009-0255", "CVE-2009-0256", "CVE-2009-0257", "CVE-2009-0258");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
if(!isnull(bver) && revcomp(a:bver, b:"4.2.4")<0) {
    txt += 'Package typo3 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
