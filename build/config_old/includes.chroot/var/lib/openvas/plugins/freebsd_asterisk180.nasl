#
#VID bb389137-21fb-11e1-89b4-001ec9578670
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID bb389137-21fb-11e1-89b4-001ec9578670
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
   asterisk18
   asterisk16

CVE-2011-4597
The SIP over UDP implementation in Asterisk Open Source 1.4.x before
1.4.43, 1.6.x before 1.6.2.21, and 1.8.x before 1.8.7.2 uses different
port numbers for responses to invalid requests depending on whether a
SIP username exists, which allows remote attackers to enumerate
usernames via a series of requests.

CVE-2011-4598
channels/chan_sip.c in Asterisk Open Source 1.6.2.x before 1.6.2.21
and 1.8.x before 1.8.7.2, when automon is enabled, allows remote
attackers to cause a denial of service (NULL pointer dereference and
daemon crash) via a crafted sequence of SIP requests.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://downloads.asterisk.org/pub/security/AST-2011-013.html
http://downloads.asterisk.org/pub/security/AST-2011-014.html
http://www.vuxml.org/freebsd/bb389137-21fb-11e1-89b4-001ec9578670.html";
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
 script_id(70595);
 script_cve_id("CVE-2011-4597", "CVE-2011-4598");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_version("$Revision: 18 $");
 script_name("FreeBSD Ports: asterisk18");


 script_description(desc);

 script_summary("FreeBSD Ports: asterisk18");

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

txt = "";
vuln = 0;
bver = portver(pkg:"asterisk18");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.7.2")<0) {
    txt += 'Package asterisk18 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"asterisk16");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.2.21")<0) {
    txt += 'Package asterisk16 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_warning(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
