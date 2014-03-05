# OpenVAS Vulnerability Test
# $Id: deb_310_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 310-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
tag_insight = "XaoS, a program for displaying fractal images, is installed setuid
root on certain architectures in order to use svgalib, which requires
access to the video hardware.  However, it is not designed for secure
setuid execution, and can be exploited to gain root privileges.

In these updated packages, the setuid bit has been removed from the
xaos binary.  Users who require the svgalib functionality should grant
these privileges only to a trusted group.

This vulnerability is exploitable in version 3.0-18 (potato) on i386
and alpha architectures, and in version 3.0-23 (woody) on the i386
architecture only.

For the stable distribution (woody) this problem has been fixed in
version 3.0-23woody1.

For the old stable distribution (potato) this problem has been fixed
in version 3.0-18potato1.

For the unstable distribution (sid) this problem has been fixed in
version 3.1r-4.

We recommend that you update your xaos package.";
tag_summary = "The remote host is missing an update to xaos
announced via advisory DSA 310-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20310-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53600);
 script_cve_id("CVE-2003-0385");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 310-1 (xaos)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 310-1 (xaos)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"xaos", ver:"3.0-18potato1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xaos", ver:"3.0-23woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
