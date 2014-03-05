# OpenVAS Vulnerability Test
# $Id: deb_2763.nasl 55 2013-11-11 15:38:51Z mime $
# Auto-generated from advisory DSA 2763-1 using nvtgen 1.0
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

tag_affected  = "pyopenssl on Debian Linux";
tag_insight   = "pyopenssl is a high-level wrapper around a subset of the OpenSSL
library.";
tag_solution  = "For the oldstable distribution (squeeze), this problem has been fixed in
version 0.10-1+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 0.13-2+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 0.13-2.1.

We recommend that you upgrade your pyopenssl packages.";
tag_summary   = "It was discovered that PyOpenSSL, a Python wrapper around the OpenSSL
library, does not properly handle certificates with NULL characters in
the Subject Alternative Name field.

A remote attacker in the position to obtain a certificate for
'www.foo.org\0.example.com' from a CA that a SSL client trusts, could
use this to spoof www.foo.org 
and conduct man-in-the-middle attacks
between the PyOpenSSL-using client and the SSL server.";
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
    script_id(892763);
    script_version("$Revision: 55 $");
    script_cve_id("CVE-2013-4314");
    script_name("Debian Security Advisory DSA 2763-1 (pyopenssl - hostname check bypassing");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-11-11 16:38:51 +0100 (Mo, 11. Nov 2013) $");
    script_tag(name: "creation_date", value:"2013-09-24 00:00:00 +0200 (Di, 24 Sep 2013)");
    script_tag(name: "cvss_base", value:"4.3");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
    script_tag(name: "risk_factor", value:"Medium");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2763.html");

    script_summary("Debian Security Advisory DSA 2763-1 (pyopenssl - hostname check bypassing)");

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
if ((res = isdpkgvuln(pkg:"python-openssl", ver:"0.10-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-openssl-dbg", ver:"0.10-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-openssl-doc", ver:"0.10-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-openssl", ver:"0.13-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-openssl-dbg", ver:"0.13-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-openssl-doc", ver:"0.13-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python3-openssl", ver:"0.13-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python3-openssl-dbg", ver:"0.13-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
