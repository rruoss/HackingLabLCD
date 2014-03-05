# OpenVAS Vulnerability Test
# $Id: deb_2093_1.nasl 14 2013-10-27 12:33:37Z jan $
# Description: Auto-generated from advisory DSA 2093-1 (ghostscript)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Two security issues have been discovered in Ghostscript, the GPL
PostScript/PDF interpreter. The Common Vulnerabilities and Exposures
project identifies the following problems:


CVE-2009-4897

It was discovered a buffer overflow that allows remote attackers to
execute arbitrary code or cause a denial of service via a crafted PDF
document containing a long name.


CVE-2010-1628

Dan Rosenberg discovered that ghostscript incorrectly handled certain
recursive Postscript files. An attacker could execute arbitrary code
via a PostScript file containing unlimited recursive procedure
invocations, which trigger memory corruption in the stack of the
interpreter.


For the stable distribution (lenny), these problems have been fixed in
version 8.62.dfsg.1-3.2lenny5

For the testing distribution (squeeze) and the unstable distribution (sid),
these problems have been fixed in version 8.71~dfsg2-4

We recommend that you upgrade your ghostscript package.";
tag_summary = "The remote host is missing an update to ghostscript
announced via advisory DSA 2093-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202093-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(67848);
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2009-4897", "CVE-2010-1628");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 2093-1 (ghostscript)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 2093-1 (ghostscript)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"gs-common", ver:"8.62.dfsg.1-3.2lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-gpl", ver:"8.62.dfsg.1-3.2lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-aladdin", ver:"8.62.dfsg.1-3.2lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript-doc", ver:"8.62.dfsg.1-3.2lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-esp", ver:"8.62.dfsg.1-3.2lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs", ver:"8.62.dfsg.1-3.2lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript-x", ver:"8.62.dfsg.1-3.2lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgs-dev", ver:"8.62.dfsg.1-3.2lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript", ver:"8.62.dfsg.1-3.2lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgs8", ver:"8.62.dfsg.1-3.2lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
