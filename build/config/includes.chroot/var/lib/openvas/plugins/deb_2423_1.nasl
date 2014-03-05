# OpenVAS Vulnerability Test
# $Id: deb_2423_1.nasl 12 2013-10-27 11:15:33Z jan $
# Description: Auto-generated from advisory DSA 2423-1 (movabletype-opensource)
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
tag_insight = "Several vulnerabilities were discovered in Movable Type, a blogging
system:

Under certain circumstances, a user who has Create Entries or
Manage Blog permissions may be able to read known files on the local
file system.

The file management system contains shell command injection
vulnerabilities, the most serious of which may lead to arbitrary OS
command execution by a user who has a permission to sign-in to the
admin script and also has a permission to upload files.

Session hijack and cross-site request forgery vulnerabilities exist in
the commenting and the community script. A remote attacker could
hijack the user session or could execute arbitrary script code on
victim's browser under the certain circumstances.

Templates which do not escape variable properly and mt-wizard.cgi
contain cross-site scripting vulnerabilities.

For the stable distribution (squeeze), these problems have been fixed
in version 4.3.8+dfsg-0+squeeze2.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 5.1.3+dfsg-1.

We recommend that you upgrade your movabletype-opensource packages.";
tag_summary = "The remote host is missing an update to movabletype-opensource
announced via advisory DSA 2423-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202423-1";

desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(71151);
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-03-12 11:33:09 -0400 (Mon, 12 Mar 2012)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 2423-1 (movabletype-opensource)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 2423-1 (movabletype-opensource)");

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
if((res = isdpkgvuln(pkg:"movabletype-opensource", ver:"4.3.8+dfsg-0+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"movabletype-plugin-core", ver:"4.3.8+dfsg-0+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"movabletype-plugin-zemanta", ver:"4.3.8+dfsg-0+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"movabletype-opensource", ver:"5.1.3+dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"movabletype-plugin-core", ver:"5.1.3+dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"movabletype-plugin-zemanta", ver:"5.1.3+dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}