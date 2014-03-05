# OpenVAS Vulnerability Test
# $Id: deb_2602.nasl 11 2013-10-27 10:12:02Z jan $
# Auto-generated from advisory DSA 2602-1 using nvtgen 1.0
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

tag_affected  = "zendframework on Debian Linux";
tag_insight   = "Extending the art & spirit of PHP, Zend Framework is based on simplicity,
object-oriented best practices, corporate friendly licensing, and a rigorously
tested agile codebase. Zend Framework is focused on building more secure,
reliable, and modern Web 2.0 applications & web services, and consuming widely
available APIs from leading vendors like Google, Amazon, Yahoo!, Flickr, as
well as API providers and cataloguers like StrikeIron and ProgrammableWeb.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 1.10.6-1squeeze2.

For the testing distribution (wheezy), this problem has been fixed in
version 1.11.13-1.1.

For the unstable distribution (sid), this problem has been fixed in
version 1.11.13-1.1.

We recommend that you upgrade your zendframework packages.";
tag_summary   = "Yury Dyachenko discovered that Zend Framework uses the PHP XML parser
in an insecure way, allowing attackers to open files and trigger HTTP
requests, potentially accessing restricted information.";
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
    script_id(892602);
    script_version("$Revision: 11 $");
    script_cve_id("CVE-2012-5657");
    script_name("Debian Security Advisory DSA 2602-1 (zendframework - XML external entity inclusion");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
    script_tag(name: "creation_date", value:"2013-01-08 00:00:00 +0100 (Di, 08 Jan 2013)");
    script_tag(name: "cvss_base", value:"5.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
    script_tag(name: "risk_factor", value:"Medium");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2602.html");

    script_summary("Debian Security Advisory DSA 2602-1 (zendframework - XML external entity inclusion)");

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
if ((res = isdpkgvuln(pkg:"zendframework", ver:"1.10.6-1squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zendframework-bin", ver:"1.10.6-1squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zendframework", ver:"1.11.13-1.1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zendframework-bin", ver:"1.11.13-1.1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zendframework-resources", ver:"1.11.13-1.1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}