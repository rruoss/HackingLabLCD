#
#VID 910486d5-ba4d-11dd-8f23-0019666436c2
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 910486d5-ba4d-11dd-8f23-0019666436c2
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
tag_insight = "The following packages are affected:
   imlib2
   imlib2-nox11

CVE-2008-5187
The load function in the XPM loader for imlib2 1.4.2, and possibly
other versions, allows attackers to cause a denial of service (crash)
and possibly execute arbitrary code via a crafted XPM file that
triggers a 'pointer arithmetic error' and a heap-based buffer
overflow, a different vulnerability than CVE-2008-2426.  NOTE: the
provenance of this information is unknown; the details are obtained
solely from third party information.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/Advisories/32796/
http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=505714#15
http://bugzilla.enlightenment.org/show_bug.cgi?id=547
http://www.vuxml.org/freebsd/910486d5-ba4d-11dd-8f23-0019666436c2.html";
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
 script_id(61913);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-11-24 23:46:43 +0100 (Mon, 24 Nov 2008)");
 script_cve_id("CVE-2008-5187");
 script_bugtraq_id(32371);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: imlib2, imlib2-nox11");


 script_description(desc);

 script_summary("FreeBSD Ports: imlib2, imlib2-nox11");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"imlib2");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.1.000_1,2")<0) {
    txt += 'Package imlib2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"imlib2-nox11");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.1.000_1,2")<0) {
    txt += 'Package imlib2-nox11 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
