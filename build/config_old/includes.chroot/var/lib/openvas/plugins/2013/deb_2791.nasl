# OpenVAS Vulnerability Test
# $Id: deb_2791.nasl 56 2013-11-11 15:55:30Z mime $
# Auto-generated from advisory DSA 2791-1 using nvtgen 1.0
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

tag_affected  = "tryton-client on Debian Linux";
tag_insight   = "Tryton is a high-level general purpose application platform written in Python
and using PostgreSQL as database engine. It is the core base of a complete
business solution.";
tag_solution  = "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.6.1-1+deb6u1.

For the stable distribution (wheezy), this problem has been fixed in
version 2.2.3-1+deb7u1.

We recommend that you upgrade your tryton-client packages.";
tag_summary   = "Cedric Krier discovered that the Tryton client does not sanitize the
file extension supplied by the server when processing reports. As a
result, a malicious server could send a report with a crafted file
extension that causes the client to write any local file to which the
user running the client has write access.";
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
    script_id(892791);
    script_version("$Revision: 56 $");
    script_cve_id("CVE-2013-4510");
    script_name("Debian Security Advisory DSA 2791-1 (tryton-client - missing input sanitization");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-11-11 16:55:30 +0100 (Mo, 11. Nov 2013) $");
    script_tag(name: "creation_date", value:"2013-11-04 00:00:00 +0100 (Mo, 04 Nov 2013)");
    script_tag(name: "cvss_base", value:"10.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
    script_tag(name: "risk_factor", value:"Critical");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2791.html");

    script_summary("Debian Security Advisory DSA 2791-1 (tryton-client - missing input sanitization)");

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
if ((res = isdpkgvuln(pkg:"tryton-client", ver:"1.6.1-1+deb6u1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tryton-client", ver:"2.2.3-1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
