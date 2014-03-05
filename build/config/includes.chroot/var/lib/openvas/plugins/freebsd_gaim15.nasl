#
#VID b6612eee-df5f-11d9-b875-0001020eed82
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
tag_insight = "The following packages are affected: gaim ja-gaim ko-gaim ru-gaim

CVE-2005-1934
Gaim before 1.3.1 allows remote attackers to cause a denial of service
(crash) via a malformed MSN message that leads to a memory allocation
of a large size, possibly due to an integer signedness error.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://gaim.sourceforge.net/security/index.php?id=19
http://www.vuxml.org/freebsd/b6612eee-df5f-11d9-b875-0001020eed82.html";
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
 script_id(53077);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2005-1934");
 script_bugtraq_id(13932);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("FreeBSD Ports: gaim, ja-gaim, ko-gaim, ru-gaim");


 script_description(desc);

 script_summary("FreeBSD Ports: gaim, ja-gaim, ko-gaim, ru-gaim");

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
bver = portver(pkg:"gaim");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.1")<0) {
    txt += 'Package gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-gaim");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.1")<0) {
    txt += 'Package ja-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ko-gaim");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.1")<0) {
    txt += 'Package ko-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ru-gaim");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.1")<0) {
    txt += 'Package ru-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_warning(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
