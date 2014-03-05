# OpenVAS Vulnerability Test
# $Id: deb_2665.nasl 39 2013-11-04 11:37:28Z mime $
# Auto-generated from advisory DSA 2665-1 using nvtgen 1.0
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

tag_affected  = "strongswan on Debian Linux";
tag_insight   = "The strongSwan VPN suite is based on the IPsec stack in standard Linux 2.6
kernels. It supports both the IKEv1 and IKEv2 protocols.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 4.4.1-5.3.

For the testing distribution (wheezy), this problem has been fixed in
version 4.5.2-1.5+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 4.6.4-7.

We recommend that you upgrade your strongswan packages.";
tag_summary   = "Kevin Wojtysiak discovered a vulnerability in strongSwan, an IPsec
based VPN solution.

When using the OpenSSL plugin for ECDSA based authentication, an empty,
zeroed or otherwise invalid signature is handled as a legitimate one.
An attacker could use a forged signature to authenticate like a legitimate
user and gain access to the VPN (and everything protected by this).

While the issue looks like CVE-2012-2388 

(RSA signature based authentication bypass), it is unrelated.";
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
    script_id(892665);
    script_version("$Revision: 39 $");
    script_cve_id("CVE-2012-2388", "CVE-2013-2944");
    script_name("Debian Security Advisory DSA 2665-1 (strongswan - authentication bypass");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-11-04 12:37:28 +0100 (Mo, 04. Nov 2013) $");
    script_tag(name: "creation_date", value:"2013-04-30 00:00:00 +0200 (Di, 30 Apr 2013)");
    script_tag(name: "cvss_base", value:"7.5");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name: "risk_factor", value:"High");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2665.html");

    script_summary("Debian Security Advisory DSA 2665-1 (strongswan - authentication bypass)");

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
if ((res = isdpkgvuln(pkg:"libstrongswan", ver:"4.4.1-5.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"strongswan", ver:"4.4.1-5.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"strongswan-dbg", ver:"4.4.1-5.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"strongswan-ikev1", ver:"4.4.1-5.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"strongswan-ikev2", ver:"4.4.1-5.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"strongswan-nm", ver:"4.4.1-5.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"strongswan-starter", ver:"4.4.1-5.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libstrongswan", ver:"4.5.2-1.5+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"strongswan", ver:"4.5.2-1.5+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"strongswan-dbg", ver:"4.5.2-1.5+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"strongswan-ikev1", ver:"4.5.2-1.5+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"strongswan-ikev2", ver:"4.5.2-1.5+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"strongswan-nm", ver:"4.5.2-1.5+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"strongswan-starter", ver:"4.5.2-1.5+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
