#
#VID 879b0242-c5b6-11e0-abd1-0017f22d6707
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 879b0242-c5b6-11e0-abd1-0017f22d6707
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: dtc

CVE-2011-0434
Multiple SQL injection vulnerabilities in Domain Technologie Control
(DTC) before 0.32.9 allow remote attackers to execute arbitrary SQL
commands via the cid parameter to (1) admin/bw_per_month.php or (2)
client/bw_per_month.php.

CVE-2011-0435
Domain Technologie Control (DTC) before 0.32.9 does not require
authentication for (1) admin/bw_per_month.php and (2)
client/bw_per_month.php, which allows remote attackers to obtain
potentially sensitive bandwidth information via a direct request.

CVE-2011-0436
The register_user function in client/new_account_form.php in Domain
Technologie Control (DTC) before 0.32.9 includes a cleartext password
in an e-mail message, which makes it easier for remote attackers to
obtain sensitive information by sniffing the network.

CVE-2011-0437
shared/inc/sql/ssh.php in the SSH accounts management implementation
in Domain Technologie Control (DTC) before 0.32.9 allows remote
authenticated users to delete arbitrary accounts via the edssh_account
parameter in a deletesshaccount Delete action.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.debian.org/security/2011/dsa-2179
http://www.vuxml.org/freebsd/879b0242-c5b6-11e0-abd1-0017f22d6707.html";
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
 script_id(70265);
 script_version("$Revision: 13 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-0434", "CVE-2011-0435", "CVE-2011-0436", "CVE-2011-0437");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: dtc");


 script_description(desc);

 script_summary("FreeBSD Ports: dtc");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"dtc");
if(!isnull(bver) && revcomp(a:bver, b:"0.32.9")<0) {
    txt += 'Package dtc version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
