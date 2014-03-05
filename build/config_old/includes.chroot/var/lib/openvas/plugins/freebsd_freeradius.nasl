#
#VID 20dfd134-1d39-11d9-9be9-000c6e8f12ef
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
tag_insight = "The following package is affected: freeradius

CVE-2004-0938
FreeRADIUS before 1.0.1 allows remote attackers to cause a denial of
service (server crash) by sending an Ascend-Send-Secret attribute
without the required leading packet.

CVE-2004-0960
FreeRADIUS before 1.0.1 allows remote attackers to cause a denial of
service (core dump) via malformed USR vendor-specific attributes (VSA)
that cause a memcpy operation with a -1 argument.

CVE-2004-0961
Memory leak in FreeRADIUS before 1.0.1 allows remote attackers to
cause a denial of service (memory exhaustion) via a series of
Access-Request packets with (1) Ascend-Send-Secret, (2)
Ascend-Recv-Secret, or (3) Tunnel-Password attributes.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.securitytracker.com/alerts/2004/Sep/1011364.html
http://www.vuxml.org/freebsd/20dfd134-1d39-11d9-9be9-000c6e8f12ef.html";
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
 script_id(52343);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-0938", "CVE-2004-0960", "CVE-2004-0961");
 script_bugtraq_id(11222);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("FreeBSD Ports: freeradius");


 script_description(desc);

 script_summary("FreeBSD Ports: freeradius");

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
bver = portver(pkg:"freeradius");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.0")>=0 && revcomp(a:bver, b:"1.0.1")<0) {
    txt += 'Package freeradius version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_warning(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
