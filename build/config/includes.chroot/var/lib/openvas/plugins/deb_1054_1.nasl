# OpenVAS Vulnerability Test
# $Id: deb_1054_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1054-1
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
version 3.7.2-3sarge1.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you upgrade your libtiff packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201054-1";
tag_summary = "The remote host is missing an update to tiff
announced via advisory DSA 1054-1.

Tavis Ormandy discovered several vulnerabilities in the TIFF library
that can lead to a denial of service or the execution of arbitrary
code.  The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2006-2024

Multiple vulnerabilities allow attackers to cause a denial of
service.

CVE-2006-2025

An integer overflows allows attackers to cause a denial of service
and possibly execute arbitrary code.

CVE-2006-2026

A double-free vulnerability allows attackers to cause a denial of
service and possibly execute arbitrary code.

For the old stable distribution (woody) these problems have been fixed
in version 3.5.5-7woody1.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(56718);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:09:45 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-2024", "CVE-2006-2025", "CVE-2006-2026", "CVE-2006-2024", "CVE-2006-2025", "CVE-2006-2026");
 script_bugtraq_id(17730,17732,17733);
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1054-1 (tiff)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1054-1 (tiff)");

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
if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.5.5-7woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff3g", ver:"3.5.5-7woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff3g-dev", ver:"3.5.5-7woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.7.2-3sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.7.2-3sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.7.2-3sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.7.2-3sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiffxx0", ver:"3.7.2-3sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
