# OpenVAS Vulnerability Test
# $Id: deb_2349_1.nasl 12 2013-10-27 11:15:33Z jan $
# Description: Auto-generated from advisory DSA 2349-1 (spip)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
tag_insight = "Two vulnerabilities have been found in SPIP, a website engine for
publishing, which allow privilege escalation to site administrator
privileges and cross-site scripting.

The oldstable distribution (lenny) doesn't include spip.

For the stable distribution (squeeze), this problem has been fixed in
version 2.1.1-3squeeze2.

For the unstable distribution (sid), this problem has been fixed in
version 2.1.12-1.

We recommend that you upgrade your spip packages.";
tag_summary = "The remote host is missing an update to spip
announced via advisory DSA 2349-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202349-1";

if(description)
{
 script_id(70562);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-11 02:30:57 -0500 (Sat, 11 Feb 2012)");
 script_name("Debian Security Advisory DSA 2349-1 (spip)");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
 script_description(desc);

 script_summary("Debian Security Advisory DSA 2349-1 (spip)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
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
if((res = isdpkgvuln(pkg:"spip", ver:"2.1.1-3squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}