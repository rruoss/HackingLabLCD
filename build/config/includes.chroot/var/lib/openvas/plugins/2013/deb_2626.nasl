# OpenVAS Vulnerability Test
# $Id: deb_2626.nasl 32 2013-10-31 13:05:08Z mime $
# Auto-generated from advisory DSA 2626-1 using nvtgen 1.0
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

tag_affected  = "lighttpd on Debian Linux";
tag_insight   = "lighttpd is a small webserver and fast webserver developed with
security in mind and a lot of features.
It has support for

* CGI, FastCGI and SSI
* virtual hosts
* URL rewriting
* authentication (plain files, htpasswd, ldap)
* transparent content compression
* conditional configuration

and configuration is straight-forward and easy.";
tag_solution  = "For the stable distribution (squeeze), these problems have been fixed in
version 1.4.28-2+squeeze1.2.

For the testing distribution (wheezy), and the unstable distribution (sid)
these problems have been fixed in version 1.4.30-1.

We recommend that you upgrade your lighttpd packages.";
tag_summary   = "Several vulnerabilities were discovered in the TLS/SSL protocol. This
update addresses these protocol vulnerabilities in lighttpd.

CVE-2009-3555 
Marsh Ray, Steve Dispensa, and Martin Rex discovered that the TLS
and SSLv3 protocols do not properly associate renegotiation
handshakes with an existing connection, which allows man-in-the-middle
attackers to insert data into HTTPS sessions. This issue is solved
in lighttpd by disabling client initiated renegotiation by default.

Those users that do actually need such renegotiations, can reenable
them via the new ssl.disable-client-renegotiation 
parameter.

CVE-2012-4929Juliano Rizzo and Thai Duong discovered a weakness in the TLS/SSL
protocol when using compression. This side channel attack, dubbed
CRIME 
, allows eavesdroppers to gather information to recover the
original plaintext in the protocol. This update disables compression.";
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
    script_id(892626);
    script_version("$Revision: 32 $");
    script_cve_id("CVE-2012-4929", "CVE-2009-3555");
    script_name("Debian Security Advisory DSA 2626-1 (lighttpd - several issues");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-10-31 14:05:08 +0100 (Do, 31. Okt 2013) $");
    script_tag(name: "creation_date", value:"2013-02-17 00:00:00 +0100 (So, 17 Feb 2013)");
    script_tag(name: "cvss_base", value:"5.8");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
    script_tag(name: "risk_factor", value:"High");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2626.html");

    script_summary("Debian Security Advisory DSA 2626-1 (lighttpd - several issues)");

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
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
