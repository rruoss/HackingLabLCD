# OpenVAS Vulnerability Test
# $Id: deb_2728.nasl 55 2013-11-11 15:38:51Z mime $
# Auto-generated from advisory DSA 2728-1 using nvtgen 1.0
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

tag_affected  = "bind9 on Debian Linux";
tag_insight   = "The Berkeley Internet Name Domain (BIND) implements an Internet domain
name server. BIND is the most widely-used name server software on the
Internet, and is supported by the Internet Software Consortium, www.isc.org.
This package provides the server and related configuration files.";
tag_solution  = "For the oldstable distribution (squeeze), this problem has been fixed in
version 1:9.7.3.dfsg-1~squeeze11.

For the stable distribution (wheezy), this problem has been fixed in
version 1:9.8.4.dfsg.P1-6+nmu2+deb7u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your bind9 packages.";
tag_summary   = "Maxim Shudrak and the HP Zero Day Initiative reported a denial of
service vulnerability in BIND, a DNS server. A specially crafted query
that includes malformed rdata can cause named daemon to terminate with
an assertion failure while rejecting the malformed query.";
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
    script_id(892728);
    script_version("$Revision: 55 $");
    script_cve_id("CVE-2013-4854");
    script_name("Debian Security Advisory DSA 2728-1 (bind9 - denial of service");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-11-11 16:38:51 +0100 (Mo, 11. Nov 2013) $");
    script_tag(name: "creation_date", value:"2013-07-27 00:00:00 +0200 (Sa, 27 Jul 2013)");
    script_tag(name: "cvss_base", value:"7.8");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
    script_tag(name: "risk_factor", value:"High");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2728.html");

    script_summary("Debian Security Advisory DSA 2728-1 (bind9 - denial of service)");

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
if ((res = isdpkgvuln(pkg:"bind9", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"host", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind9-60", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdns69", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisc62", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccc60", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccfg62", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblwres60", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lwresd", ver:"1:9.7.3.dfsg-1~squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"host", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind9-80", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdns88", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisc84", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccc80", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccfg82", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblwres80", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lwresd", ver:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
