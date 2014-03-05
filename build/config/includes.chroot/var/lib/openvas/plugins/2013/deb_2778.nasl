# OpenVAS Vulnerability Test
# $Id: deb_2778.nasl 55 2013-11-11 15:38:51Z mime $
# Auto-generated from advisory DSA 2778-1 using nvtgen 1.0
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

tag_affected  = "libapache2-mod-fcgid on Debian Linux";
tag_insight   = "mod_fcgid is a high performance alternative to mod_cgi or mod_cgid,
which starts a sufficient number instances of the CGI program to handle
concurrent requests, and these programs remain running to handle further
incoming requests. It is favored by the PHP developers, for example,
as a preferred alternative to running mod_php in-process, delivering
very similar performance.";
tag_solution  = "For the oldstable distribution (squeeze), this problem has been fixed in
version 1:2.3.6-1+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 1:2.3.6-1.2+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 1:2.3.9-1.

We recommend that you upgrade your libapache2-mod-fcgid packages.";
tag_summary   = "Robert Matthews discovered that the Apache FCGID module, a FastCGI
implementation for Apache HTTP Server, fails to perform adequate
boundary checks on user-supplied input. This may allow a remote attacker
to cause a heap-based buffer overflow, resulting in a denial of service
or potentially allowing the execution of arbitrary code.";
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
    script_id(892778);
    script_version("$Revision: 55 $");
    script_cve_id("CVE-2013-4365");
    script_name("Debian Security Advisory DSA 2778-1 (libapache2-mod-fcgid - heap-based buffer overflow");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-11-11 16:38:51 +0100 (Mo, 11. Nov 2013) $");
    script_tag(name: "creation_date", value:"2013-10-12 00:00:00 +0200 (Sa, 12 Okt 2013)");
    script_tag(name: "cvss_base", value:"5.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
    script_tag(name: "risk_factor", value:"Medium");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2778.html");

    script_summary("Debian Security Advisory DSA 2778-1 (libapache2-mod-fcgid - heap-based buffer overflow)");

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
if ((res = isdpkgvuln(pkg:"libapache2-mod-fcgid", ver:"1:2.3.6-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-fcgid-dbg", ver:"1:2.3.6-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-fcgid", ver:"1:2.3.6-1.2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-fcgid-dbg", ver:"1:2.3.6-1.2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
