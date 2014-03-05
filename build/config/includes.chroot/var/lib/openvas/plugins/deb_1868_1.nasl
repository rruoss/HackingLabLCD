# OpenVAS Vulnerability Test
# $Id: deb_1868_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1868-1 (kde4libs)
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
tag_insight = "Several security issues have been discovered in kde4libs, core libraries
for all KDE 4 applications. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2009-1690

It was discovered that there is a use-after-free flaw in handling
certain DOM event handlers. This could lead to the execution of
arbitrary code, when visiting a malicious website.

CVE-2009-1698

It was discovered that there could be an uninitialised pointer when
handling a Cascading Style Sheets (CSS) attr function call. This could
lead to the execution of arbitrary code, when visiting a malicious
website.

CVE-2009-1687

It was discovered that the JavaScript garbage collector does not handle
allocation failures properly, which could lead to the execution of
arbitrary code when visiting a malicious website.


For the stable distribution (lenny), these problems have been fixed in
version 4:4.1.0-3+lenny1.

The oldstable distribution (etch) does not contain kde4libs.

For the testing distribution (squeeze), these problems will be fixed
soon.

For the unstable distribution (sid), these problems have been fixed in
version 4:4.3.0-1.


We recommend that you upgrade your kde4libs packages.";
tag_summary = "The remote host is missing an update to kde4libs
announced via advisory DSA 1868-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201868-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(64749);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2009-1690", "CVE-2009-1698", "CVE-2009-1687");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1868-1 (kde4libs)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1868-1 (kde4libs)");

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
if ((res = isdpkgvuln(pkg:"kdelibs5-data", ver:"4.1.0-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-bin", ver:"4.1.0-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs5-dbg", ver:"4.1.0-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs5-dev", ver:"4.1.0-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs5", ver:"4.1.0-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
