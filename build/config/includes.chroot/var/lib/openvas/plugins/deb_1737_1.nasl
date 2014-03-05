# OpenVAS Vulnerability Test
# $Id: deb_1737_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1737-1 (wesnoth)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several security issues have been discovered in wesnoth, a fantasy
turn-based strategy game. The Common Vulnerabilities and Exposures
project identifies the following problems:


CVE-2009-0366

Daniel Franke discovered that the wesnoth server is prone to a denial of
service attack when receiving special crafted compressed data.

CVE-2009-0367

Daniel Franke discovered that the sandbox implementation for the python
AIs can be used to execute arbitrary python code on wesnoth clients. In
order to prevent this issue, the python support has been disabled. A
compatibility patch was included, so that the affected campagne is still
working properly.


For the stable distribution (lenny), these problems have been fixed in
version 1.4.4-2+lenny1.

For the oldstable distribution (etch), these problems have been fixed
in version 1.2-5.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems have been fixed in version 1.4.7-4.

We recommend that you upgrade your wesnoth packages.";
tag_summary = "The remote host is missing an update to wesnoth
announced via advisory DSA 1737-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201737-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(63534);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-13 19:24:56 +0100 (Fri, 13 Mar 2009)");
 script_cve_id("CVE-2009-0366", "CVE-2009-0367");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1737-1 (wesnoth)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1737-1 (wesnoth)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"wesnoth-data", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-music", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-tsg", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-trow", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-ttb", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-ei", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-utbs", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-httt", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-server", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-editor", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-aoi", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-sof", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-thot", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-did", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-sotbe", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-l", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-tools", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-all", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-nr", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wesnoth-dbg", ver:"1.4.4-2+lenny1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
