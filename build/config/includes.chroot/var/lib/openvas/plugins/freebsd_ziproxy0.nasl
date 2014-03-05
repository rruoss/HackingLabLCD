#
#VID b43004b8-6a53-11df-bc7b-0245fb008c0b
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID b43004b8-6a53-11df-bc7b-0245fb008c0b
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: ziproxy

CVE-2010-1513
Multiple integer overflows in src/image.c in Ziproxy before 3.0.1
allow remote attackers to execute arbitrary code via (1) a large JPG
image, related to the jpg2bitmap function or (2) a large PNG image,
related to the png2bitmap function, leading to heap-based buffer
overflows.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://ziproxy.sourceforge.net/#news
http://secunia.com/advisories/39941
http://sourceforge.net/mailarchive/message.php?msg_name=201005210019.37119.dancab%40gmx.net
http://www.vuxml.org/freebsd/b43004b8-6a53-11df-bc7b-0245fb008c0b.html";
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
 script_id(67408);
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-03 22:55:24 +0200 (Thu, 03 Jun 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-1513");
 script_bugtraq_id(40344);
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: ziproxy");


 script_description(desc);

 script_summary("FreeBSD Ports: ziproxy");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"ziproxy");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.1")<0) {
    txt += 'Package ziproxy version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
