# OpenVAS Vulnerability Test
# $Id: deb_2731.nasl 55 2013-11-11 15:38:51Z mime $
# Auto-generated from advisory DSA 2731-1 using nvtgen 1.0
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

tag_affected  = "libgcrypt11 on Debian Linux";
tag_insight   = "libgcrypt contains cryptographic functions. Many important free
ciphers, hash algorithms and public key signing algorithms have been
implemented:
arcfour, blowfish, cast5, DSA, DSA2, des, 3DES, elgamal, MD5, rijndael,
RMD160, RSA, SEED, SHA1, SHA-384, SHA-512, twofish, tiger.";
tag_solution  = "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.4.5-2+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 1.5.0-5+deb7u1.

For the testing distribution (jessie) and unstable distribution (sid),
this problem has been fixed in version 1.5.3-1.

We recommend that you upgrade your libgcrypt11 packages.";
tag_summary   = "Yarom and Falkner discovered that RSA secret keys in applications using
the libgcrypt11 library, for example GnuPG 2.x, could be leaked via
a side channel attack, where a malicious local user could obtain private
key information from another user on the system.";
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
    script_id(892731);
    script_version("$Revision: 55 $");
    script_cve_id("CVE-2013-4242");
    script_name("Debian Security Advisory DSA 2731-1 (libgcrypt11 - information leak");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-11-11 16:38:51 +0100 (Mo, 11. Nov 2013) $");
    script_tag(name: "creation_date", value:"2013-07-29 00:00:00 +0200 (Mo, 29 Jul 2013)");
    script_tag(name: "cvss_base", value:"1.9");
    script_tag(name: "cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
    script_tag(name: "risk_factor", value:"Low");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2731.html");

    script_summary("Debian Security Advisory DSA 2731-1 (libgcrypt11 - information leak)");

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
if ((res = isdpkgvuln(pkg:"libgcrypt11", ver:"1.4.5-2+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcrypt11-dbg", ver:"1.4.5-2+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcrypt11-dev", ver:"1.4.5-2+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcrypt11-doc", ver:"1.4.5-2+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcrypt11", ver:"1.5.0-5+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcrypt11-dbg", ver:"1.5.0-5+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcrypt11-dev", ver:"1.5.0-5+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcrypt11-doc", ver:"1.5.0-5+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcrypt11-udeb", ver:"1.5.0-5+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}