# OpenVAS Vulnerability Test
# $Id: deb_2628.nasl 32 2013-10-31 13:05:08Z mime $
# Auto-generated from advisory DSA 2628-1 using nvtgen 1.0
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

tag_affected  = "nss-pam-ldapd on Debian Linux";
tag_insight   = "nss-pam-ldap provides a Name Service Switch module that allows your LDAP
server to provide user account, group, host name, alias, netgroup, and
basically any other information that you would normally get from /etc flat
files or NIS.";
tag_solution  = "For the stable distribution (squeeze) this problem has been fixed in
version 0.7.15+squeeze4.

For the testing distribution (wheezy), this problem has been fixed in
version 0.8.10-3.

For the unstable distribution (sid), this problem has been fixed in
version 0.8.10-3.

We recommend that you upgrade your nss-pam-ldapd packages.";
tag_summary   = "Garth Mollett discovered that a file descriptor overflow issue in the
use of FD_SET() in nss-pam-ldapd, which provides NSS and PAM modules for
using LDAP as a naming service, can lead to a stack-based buffer
overflow. An attacker could, under some circumstances, use this flaw to
cause a process that has the NSS or PAM module loaded to crash or
potentially execute arbitrary code.";
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
    script_id(892628);
    script_version("$Revision: 32 $");
    script_cve_id("CVE-2013-0288");
    script_name("Debian Security Advisory DSA 2628-1 (nss-pam-ldapd - buffer overflow");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-10-31 14:05:08 +0100 (Do, 31. Okt 2013) $");
    script_tag(name: "creation_date", value:"2013-06-18 00:00:00 +0200 (Di, 18 Jun 2013)");
    script_tag(name: "cvss_base", value:"6.8");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
    script_tag(name: "risk_factor", value:"High");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2628.html");

    script_summary("Debian Security Advisory DSA 2628-1 (nss-pam-ldapd - buffer overflow)");

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
if ((res = isdpkgvuln(pkg:"libnss-ldapd", ver:"0.7.15+squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-ldapd", ver:"0.7.15+squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nslcd", ver:"0.7.15+squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss-ldapd", ver:"0.8.10-3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-ldapd", ver:"0.8.10-3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nslcd", ver:"0.8.10-3", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
