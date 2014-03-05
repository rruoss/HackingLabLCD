# OpenVAS Vulnerability Test
# $Id: deb_2646.nasl 32 2013-10-31 13:05:08Z mime $
# Auto-generated from advisory DSA 2646-1 using nvtgen 1.0
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

tag_affected  = "typo3-src on Debian Linux";
tag_insight   = "TYPO3 is a free Open Source content management system for enterprise purposes
on the web and in intranets. It offers full flexibility and extendability while
featuring an accomplished set of ready-made interfaces, functions and modules.";
tag_solution  = "For the stable distribution (squeeze), these problems have been fixed in
version 4.3.9+dfsg1-1+squeeze8.

For the testing distribution (wheezy), these problems have been fixed in
version 4.5.19+dfsg1-5.

For the unstable distribution (sid), these problems have been fixed in
version 4.5.19+dfsg1-5.

We recommend that you upgrade your typo3-src packages.";
tag_summary   = "TYPO3, a PHP-based content management system, was found vulnerable to several vulnerabilities.

CVE-2013-1842 
Helmut Hummel and Markus Opahle discovered that the Extbase database layer
was not correctly sanitizing user input when using the Query object model.
This can lead to SQL injection by a malicious user inputing crafted
relation values.

CVE-2013-1843 
Missing user input validation in the access tracking mechanism could lead
to arbitrary URL redirection.

Note: the fix will break already published links. Upstream advisory
TYPO3-CORE-SA-2013-001 

has more information on how to mitigate that.";
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
    script_id(892646);
    script_version("$Revision: 32 $");
    script_cve_id("CVE-2013-1842", "CVE-2013-1843");
    script_name("Debian Security Advisory DSA 2646-1 (typo3-src - several vulnerabilities");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-10-31 14:05:08 +0100 (Do, 31. Okt 2013) $");
    script_tag(name: "creation_date", value:"2013-03-15 00:00:00 +0100 (Fr, 15 M�r 2013)");
    script_tag(name: "cvss_base", value:"7.5");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name: "risk_factor", value:"High");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2646.html");

    script_summary("Debian Security Advisory DSA 2646-1 (typo3-src - several vulnerabilities)");

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
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.3.9+dfsg1-1+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-database", ver:"4.3.9+dfsg1-1+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-src-4.3", ver:"4.3.9+dfsg1-1+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.5.19+dfsg1-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-database", ver:"4.5.19+dfsg1-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-dummy", ver:"4.5.19+dfsg1-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-src-4.5", ver:"4.5.19+dfsg1-5", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
