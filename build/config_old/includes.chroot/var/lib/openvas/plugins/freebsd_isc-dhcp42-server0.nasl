#
#VID 1800886c-3dde-11e1-89b4-001ec9578670
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 1800886c-3dde-11e1-89b4-001ec9578670
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
tag_insight = "The following package is affected: isc-dhcp42-server

CVE-2011-4868
The logging functionality in dhcpd in ISC DHCP before 4.2.3-P2, when
using Dynamic DNS (DDNS) and issuing IPv6 addresses, does not properly
handle the DHCPv6 lease structure, which allows remote attackers to
cause a denial of service (NULL pointer dereference and daemon crash)
via crafted packets related to a lease-status update.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://www.isc.org/software/dhcp/advisories/cve-2011-4868
http://www.vuxml.org/freebsd/1800886c-3dde-11e1-89b4-001ec9578670.html";
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
 script_id(70757);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"6.1");
 script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2011-4868");
 script_tag(name:"risk_factor", value:"High");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)");
 script_name("FreeBSD Ports: isc-dhcp42-server");


 script_description(desc);

 script_summary("FreeBSD Ports: isc-dhcp42-server");

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
txt = "";
bver = portver(pkg:"isc-dhcp42-server");
if(!isnull(bver) && revcomp(a:bver, b:"4.2.3_2")<0) {
    txt += 'Package isc-dhcp42-server version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
