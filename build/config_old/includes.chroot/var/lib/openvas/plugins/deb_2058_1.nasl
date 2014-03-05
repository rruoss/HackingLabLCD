# OpenVAS Vulnerability Test
# $Id: deb_2058_1.nasl 14 2013-10-27 12:33:37Z jan $
# Description: Auto-generated from advisory DSA 2058-1 (glibc, eglibc)
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
tag_insight = "Several vulnerabilities have been discovered in the GNU C Library (aka
glibc) and its derivatives. The Common Vulnerabilities and Exposures
project identifies the following problems:


CVE-2008-1391, CVE-2009-4880, CVE-2009-4881

Maksymilian Arciemowicz discovered that the GNU C library did not
correctly handle integer overflows in the strfmon family of
functions. If a user or automated system were tricked into
processing a specially crafted format string, a remote attacker
could crash applications, leading to a denial of service.


CVE-2010-0296

Jeff Layton and Dan Rosenberg discovered that the GNU C library did
not correctly handle newlines in the mntent family of functions. If
a local attacker were able to inject newlines into a mount entry
through other vulnerable mount helpers, they could disrupt the
system or possibly gain root privileges.


CVE-2010-0830

Dan Rosenberg discovered that the GNU C library did not correctly
validate certain ELF program headers.  If a user or automated system
were tricked into verifying a specially crafted ELF program, a
remote attacker could execute arbitrary code with user privileges.

For the stable distribution (lenny), these problems have been fixed in
version 2.7-18lenny4 of the glibc package.

For the testing distribution (squeeze), these problems will be fixed soon.

For the unstable distribution (sid), these problems has been fixed in
version 2.1.11-1 of the eglibc package.

We recommend that you upgrade your glibc or eglibc packages.";
tag_summary = "The remote host is missing an update to glibc, eglibc
announced via advisory DSA 2058-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202058-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(67542);
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-10 21:49:43 +0200 (Thu, 10 Jun 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2008-1391", "CVE-2009-4880", "CVE-2009-4881", "CVE-2010-0296", "CVE-2010-0830");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 2058-1 (glibc, eglibc)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 2058-1 (glibc, eglibc)");

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
if ((res = isdpkgvuln(pkg:"glibc-source", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"locales", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"glibc-doc", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6.1-pic", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6.1-dbg", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6.1-dev", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6.1", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6.1-prof", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nscd", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6.1-alphaev67", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"locales-all", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-dev-i386", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-i386", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-dbg", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-prof", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-dev", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-pic", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-i686", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-xen", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-amd64", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-dev-amd64", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-dev-mips64", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-mipsn32", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-mips64", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-dev-mipsn32", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-ppc64", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-dev-ppc64", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-dev-s390x", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-s390x", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-sparc64", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-dev-sparc64", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc6-sparcv9b", ver:"2.7-18lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
