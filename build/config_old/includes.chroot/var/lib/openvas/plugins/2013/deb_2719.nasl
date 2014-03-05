# OpenVAS Vulnerability Test
# $Id: deb_2719.nasl 49 2013-11-07 12:55:54Z mime $
# Auto-generated from advisory DSA 2719-1 using nvtgen 1.0
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

tag_affected  = "poppler on Debian Linux";
tag_insight   = "Poppler is a PDF rendering library based on the xpdf PDF viewer.";
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 0.12.4-1.2+squeeze3.

For the stable (wheezy), testing (jessie), and unstable (sid)
distributions, these problems have been fixed in version 0.18.4-6.

We recommend that you upgrade your poppler packages.";
tag_summary   = "Multiple vulnerabilities were discovered in the poppler PDF rendering
library.

CVE-2013-1788 
Multiple invalid memory access issues, which could potentially lead
to arbitrary code execution if the user were tricked into opening a
malformed PDF document.

CVE-2013-1790 
An uninitialized memory issue, which could potentially lead to
arbitrary code execution if the user were tricked into opening a
malformed PDF document.";
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
    script_id(892719);
    script_version("$Revision: 49 $");
    script_cve_id("CVE-2013-1790", "CVE-2013-1788");
    script_name("Debian Security Advisory DSA 2719-1 (poppler - several vulnerabilities");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-11-07 13:55:54 +0100 (Do, 07. Nov 2013) $");
    script_tag(name: "creation_date", value:"2013-07-10 00:00:00 +0200 (Mi, 10 Jul 2013)");
    script_tag(name: "cvss_base", value:"6.8");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
    script_tag(name: "risk_factor", value:"High");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2719.html");

    script_summary("Debian Security Advisory DSA 2719-1 (poppler - several vulnerabilities)");

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
if ((res = isdpkgvuln(pkg:"libpoppler-dev", ver:"0.12.4-1.2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-glib-dev", ver:"0.12.4-1.2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-glib4", ver:"0.12.4-1.2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-qt-dev", ver:"0.12.4-1.2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-qt2", ver:"0.12.4-1.2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-qt4-3", ver:"0.12.4-1.2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-qt4-dev", ver:"0.12.4-1.2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler5", ver:"0.12.4-1.2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"poppler-dbg", ver:"0.12.4-1.2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"poppler-utils", ver:"0.12.4-1.2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gir1.2-poppler-0.18", ver:"0.18.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-cpp-dev", ver:"0.18.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-cpp0", ver:"0.18.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-dev", ver:"0.18.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-glib-dev", ver:"0.18.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-glib8", ver:"0.18.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-private-dev", ver:"0.18.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-qt4-3", ver:"0.18.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-qt4-dev", ver:"0.18.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler19", ver:"0.18.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"poppler-dbg", ver:"0.18.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"poppler-utils", ver:"0.18.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
