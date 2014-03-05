# OpenVAS Vulnerability Test
# $Id: deb_1805_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1805-1 (pidgin)
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
tag_insight = "Several vulnerabilities have been discovered in Pidgin, a graphical
multi-protocol instant messaging client. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2009-1373

A buffer overflow in the Jabber file transfer code may lead to
denial of service or the execution of arbitrary code.

CVE-2009-1375

Memory corruption in an internal library may lead to denial of
service.

CVE-2009-1376

The patch provided for the security issue tracked as CVE-2008-2927
- integer overflows in the MSN protocol handler - was found to be
incomplete.

The old stable distribution (etch) is affected under the source package
name gaim. However, due to build problems the updated packages couldn't
be released along with the stable version. It will be released once the
build problem is resolved.

For the stable distribution (lenny), these problems have been fixed in
version 2.4.3-4lenny2.

For the unstable distribution (sid), these problems have been fixed in
version 2.5.6-1.

We recommend that you upgrade your pidgin packages.";
tag_summary = "The remote host is missing an update to pidgin
announced via advisory DSA 1805-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201805-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(64038);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-25 20:59:33 +0200 (Mon, 25 May 2009)");
 script_cve_id("CVE-2009-1373", "CVE-2009-1375", "CVE-2009-1376", "CVE-2008-2927");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1805-1 (pidgin)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1805-1 (pidgin)");

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
if ((res = isdpkgvuln(pkg:"libpurple-bin", ver:"2.4.3-4lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpurple-dev", ver:"2.4.3-4lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"finch-dev", ver:"2.4.3-4lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pidgin-dev", ver:"2.4.3-4lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pidgin-data", ver:"2.4.3-4lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pidgin", ver:"2.4.3-4lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pidgin-dbg", ver:"2.4.3-4lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"finch", ver:"2.4.3-4lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpurple0", ver:"2.4.3-4lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
