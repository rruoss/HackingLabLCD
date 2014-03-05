#
#VID 4bd33bc5-0cd6-11e0-bfa4-001676740879
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 4bd33bc5-0cd6-11e0-bfa4-001676740879
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
tag_insight = "The following packages are affected:
   tor
   tor-devel

CVE-2010-1676
Heap-based buffer overflow in Tor before 0.2.1.28 and 0.2.2.x before
0.2.2.20-alpha allows remote attackers to cause a denial of service
(daemon crash) or possibly execute arbitrary code via unspecified
vectors.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://gitweb.torproject.org/tor.git/blob/release-0.2.1:/ChangeLog
https://gitweb.torproject.org/tor.git/blob/release-0.2.2:/ChangeLog
http://archives.seul.org/or/announce/Dec-2010/msg00000.html
http://archives.seul.org/or/talk/Dec-2010/msg00167.html
http://www.vuxml.org/freebsd/4bd33bc5-0cd6-11e0-bfa4-001676740879.html";
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
 script_id(68827);
 script_version("$Revision: 13 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-1676");
 script_bugtraq_id(45500);
 script_tag(name:"risk_factor", value:"Critical");
 script_name("FreeBSD Ports: tor");


 script_description(desc);

 script_summary("FreeBSD Ports: tor");

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
bver = portver(pkg:"tor");
if(!isnull(bver) && revcomp(a:bver, b:"0.2.1.28")<0) {
    txt += 'Package tor version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tor-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0.2.2.20-alpha")<0) {
    txt += 'Package tor-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}