#
#VID d754b7d2-b6a7-11df-826c-e464a695cb21
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID d754b7d2-b6a7-11df-826c-e464a695cb21
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
   wget
   wget-devel

CVE-2010-2252
GNU Wget 1.12 and earlier uses a server-provided filename instead of
the original URL to determine the destination filename of a download,
which allows remote servers to create or overwrite arbitrary files via
a 3xx redirect to a URL with a .wgetrc filename followed by a 3xx
redirect to a URL with a crafted filename, and possibly execute
arbitrary code as a consequence of writing to a dotfile in a home
directory.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://bugzilla.redhat.com/show_bug.cgi?id=602797
http://www.vuxml.org/freebsd/d754b7d2-b6a7-11df-826c-e464a695cb21.html";
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
 script_id(67997);
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-10-10 19:35:00 +0200 (Sun, 10 Oct 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-2252");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: wget, wget-devel");


 script_description(desc);

 script_summary("FreeBSD Ports: wget, wget-devel");

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
bver = portver(pkg:"wget");
if(!isnull(bver) && revcomp(a:bver, b:"1.12_1")<=0) {
    txt += 'Package wget version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"wget-devel");
if(!isnull(bver) && revcomp(a:bver, b:"1.12_1")<=0) {
    txt += 'Package wget-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
