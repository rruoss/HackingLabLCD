# OpenVAS Vulnerability Test
# $Id: deb_2754.nasl 55 2013-11-11 15:38:51Z mime $
# Auto-generated from advisory DSA 2754-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the Free
# Software Foundation
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

tag_affected  = "exactimage on Debian Linux";
tag_insight   = "ExactImage is a fast C++ image processing library. Unlike many other library
frameworks it allows operation in several color spaces and bit depths
natively, resulting in low memory and computational requirements.";
tag_solution  = "For the oldstable distribution (squeeze), this problem has been fixed in
version 0.8.1-3+deb6u3.

For the stable distribution (wheezy), this problem has been fixed in
version 0.8.5-5+deb7u3.

For the testing distribution (jessie) and the unstable distribution
(sid), this problem has been fixed in version 0.8.9-2.

We recommend that you upgrade your exactimage packages.";
tag_summary   = "It was discovered that exactimage, a fast image processing library,
does not correctly handle error conditions of the embedded copy of
dcraw. This could result in a crash or other behaviour in an
application using the library due to an uninitialized variable being
passed to longjmp.

This is a different issue than CVE-2013-1438 
/DSA-2748-1.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

desc = "Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

if(description)
{
    script_id(892754);
    script_version("$Revision: 55 $");
    script_cve_id("CVE-2013-1438", "CVE-2013-1441");
    script_name("Debian Security Advisory DSA 2754-1 (exactimage - denial of service");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-11-11 16:38:51 +0100 (Mo, 11. Nov 2013) $");
    script_tag(name: "creation_date", value:"2013-09-10 00:00:00 +0200 (Di, 10 Sep 2013)");
    script_tag(name: "cvss_base", value:"10.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
    script_tag(name: "risk_factor", value:"Critical");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2754.html");

    script_summary("Debian Security Advisory DSA 2754-1 (exactimage - denial of service)");

    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
        script_tag(name: "affected",  value: tag_affected);
        script_tag(name: "insight",   value: tag_insight);
#        script_tag(name: "impact",    value: tag_impact);
        script_tag(name: "solution",  value: tag_solution);
        script_tag(name: "summary",   value: tag_summary);
        script_tag(name: "vuldetect", value: tag_vuldetect);
    }

    exit(0);
}

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"exactimage", ver:"0.8.1-3+deb6u3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"exactimage-dbg", ver:"0.8.1-3+deb6u3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"exactimage-perl", ver:"0.8.1-3+deb6u3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libexactimage-perl", ver:"0.8.1-3+deb6u3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-exactimage", ver:"0.8.1-3+deb6u3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-exactimage", ver:"0.8.1-3+deb6u3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"edisplay", ver:"0.8.5-5+deb7u3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"exactimage", ver:"0.8.5-5+deb7u3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"exactimage-dbg", ver:"0.8.5-5+deb7u3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libexactimage-perl", ver:"0.8.5-5+deb7u3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-exactimage", ver:"0.8.5-5+deb7u3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-exactimage", ver:"0.8.5-5+deb7u3", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
