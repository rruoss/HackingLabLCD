#
#VID f866d2af-bbba-11df-8a8d-0008743bf21a
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID f866d2af-bbba-11df-8a8d-0008743bf21a
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
   vim6
   vim6+ruby

CVE-2008-3432
Heap-based buffer overflow in the mch_expand_wildcards function in
os_unix.c in Vim 6.2 and 6.3 allows user-assisted attackers to execute
arbitrary code via shell metacharacters in filenames, as demonstrated
by the netrw.v3 test case.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.openwall.com/lists/oss-security/2008/07/15/4
http://www.vuxml.org/freebsd/f866d2af-bbba-11df-8a8d-0008743bf21a.html";
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
 script_id(67993);
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-10-10 19:35:00 +0200 (Sun, 10 Oct 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2008-3432");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: vim6, vim6+ruby");


 script_description(desc);

 script_summary("FreeBSD Ports: vim6, vim6+ruby");

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
bver = portver(pkg:"vim6");
if(!isnull(bver) && revcomp(a:bver, b:"6.2.429")>=0 && revcomp(a:bver, b:"6.3.62")<0) {
    txt += 'Package vim6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"vim6+ruby");
if(!isnull(bver) && revcomp(a:bver, b:"6.2.429")>=0 && revcomp(a:bver, b:"6.3.62")<0) {
    txt += 'Package vim6+ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
