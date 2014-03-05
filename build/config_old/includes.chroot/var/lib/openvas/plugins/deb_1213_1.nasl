# OpenVAS Vulnerability Test
# $Id: deb_1213_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1213-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 6:6.0.6.2-2.8.

For the upcoming stable distribution (etch) these problems have been
fixed in version 7:6.2.4.5.dfsg1-0.11.

For the unstable distribution (sid) these problems have been fixed in
version 7:6.2.4.5.dfsg1-0.11.

We recommend that you upgrade your imagemagick packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201213-1";
tag_summary = "The remote host is missing an update to imagemagick
announced via advisory DSA 1213-1.

Several remote vulnerabilities have been discovered in Imagemagick,
a collection of image manipulation programs, which may lead to the
execution of arbitrary code. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2006-0082

Daniel Kobras discovered that Imagemagick is vulnerable to format
string attacks in the filename parsing code.

CVE-2006-4144

Damian Put discovered that Imagemagick is vulnerable to buffer
overflows in the module for SGI images.

CVE-2006-5456

M Joonas Pihlaja discovered that Imagemagick is vulnerable to buffer
overflows in the module for DCM and PALM images.

CVE-2006-5868

Daniel Kobras discovered that Imagemagick is vulnerable to buffer
overflows in the module for SGI images.

This update also adresses regressions in the XCF codec, which were
introduced in the previous security update.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(57586);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-0082", "CVE-2006-4144", "CVE-2006-5456", "CVE-2006-5868");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1213-1 (imagemagick)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1213-1 (imagemagick)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"imagemagick", ver:"6.0.6.2-2.8", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++6", ver:"6.0.6.2-2.8", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++6-dev", ver:"6.0.6.2-2.8", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick6", ver:"6.0.6.2-2.8", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick6-dev", ver:"6.0.6.2-2.8", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"perlmagick", ver:"6.0.6.2-2.8", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
