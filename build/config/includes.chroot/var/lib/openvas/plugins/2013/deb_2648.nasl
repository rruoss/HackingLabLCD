# OpenVAS Vulnerability Test
# $Id: deb_2648.nasl 39 2013-11-04 11:37:28Z mime $
# Auto-generated from advisory DSA 2648-1 using nvtgen 1.0
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

tag_affected  = "firebird2.5 on Debian Linux";
tag_insight   = "Firebird is a relational database offering many ANSI SQL-99 features that
runs on Linux, Windows, and a variety of Unix platforms. Firebird offers
excellent concurrency, high performance, and powerful language support
for stored procedures and triggers.";
tag_solution  = "For the stable distribution (squeeze), these problems have been fixed in
version 2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your firebird2.5 packages.";
tag_summary   = "A buffer overflow was discovered in the Firebird database server, which
could result in the execution of arbitrary code. In addition, a denial
of service vulnerability was discovered in the TraceManager.";
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
    script_id(892648);
    script_version("$Revision: 39 $");
    script_cve_id("CVE-2013-2492", "CVE-2012-5529");
    script_name("Debian Security Advisory DSA 2648-1 (firebird2.5 - several vulnerabilities");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-11-04 12:37:28 +0100 (Mo, 04. Nov 2013) $");
    script_tag(name: "creation_date", value:"2013-03-15 00:00:00 +0100 (Fr, 15 Mär 2013)");
    script_tag(name: "cvss_base", value:"6.8");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
    script_tag(name: "risk_factor", value:"High");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2648.html");

    script_summary("Debian Security Advisory DSA 2648-1 (firebird2.5 - several vulnerabilities)");

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
if ((res = isdpkgvuln(pkg:"firebird2.5-classic", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firebird2.5-classic-common", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firebird2.5-common", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firebird2.5-common-doc", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firebird2.5-dev", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firebird2.5-doc", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firebird2.5-examples", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firebird2.5-server-common", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firebird2.5-super", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firebird2.5-superclassic", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libfbclient2", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libfbembed2.5", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libib-util", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
