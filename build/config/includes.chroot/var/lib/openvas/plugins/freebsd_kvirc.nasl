#
#VID 8685d412-8468-11df-8d45-001d7d9eb79a
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 8685d412-8468-11df-8d45-001d7d9eb79a
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
tag_insight = "The following packages are affected:
   kvirc
   kvirc-devel

CVE-2010-2451
Multiple format string vulnerabilities in the DCC functionality in
KVIrc 3.4 and 4.0 have unspecified impact and remote attack vectors.

CVE-2010-2452
Directory traversal vulnerability in the DCC functionality in KVIrc
3.4 and 4.0 allows remote attackers to overwrite arbitrary files via
unknown vectors.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://lists.omnikron.net/pipermail/kvirc/2010-May/000867.html
http://www.vuxml.org/freebsd/8685d412-8468-11df-8d45-001d7d9eb79a.html";
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
 script_id(67648);
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-06 02:35:12 +0200 (Tue, 06 Jul 2010)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-2451", "CVE-2010-2452");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("FreeBSD Ports: kvirc, kvirc-devel");


 script_description(desc);

 script_summary("FreeBSD Ports: kvirc, kvirc-devel");

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
bver = portver(pkg:"kvirc");
if(!isnull(bver) && revcomp(a:bver, b:"4.0.0")<0) {
    txt += 'Package kvirc version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"kvirc-devel");
if(!isnull(bver) && revcomp(a:bver, b:"4.0.0")<0) {
    txt += 'Package kvirc-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
