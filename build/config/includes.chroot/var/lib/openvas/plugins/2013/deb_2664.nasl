# OpenVAS Vulnerability Test
# $Id: deb_2664.nasl 39 2013-11-04 11:37:28Z mime $
# Auto-generated from advisory DSA 2664-1 using nvtgen 1.0
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

tag_affected  = "stunnel4 on Debian Linux";
tag_insight   = "The stunnel program is designed to work as SSL encryption
wrapper between remote client and local (inetd-startable) or
remote server. The concept is that having non-SSL aware daemons
running on your system you can easily setup them to
communicate with clients over secure SSL channel.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 3:4.29-1+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 3:4.53-1.1.

For the unstable distribution (sid), this problem has been fixed in
version 3:4.53-1.1.

We recommend that you upgrade your stunnel4 packages.";
tag_summary   = "Stunnel, a program designed to work as an universal SSL tunnel for
network daemons, is prone to a buffer overflow vulnerability when using
the Microsoft NT LAN Manager (NTLM) authentication
(protocolAuthentication = NTLM) together with the connect protocol method (protocol = connect). With these prerequisites
and using stunnel4 in SSL client mode (client = yes 
) on a 64 bit
host, an attacker could possibly execute arbitrary code with the
privileges of the stunnel process, if the attacker can either control
the specified proxy server or perform man-in-the-middle attacks on the
tcp session between stunnel and the proxy sever.

Note that for the testing distribution (wheezy) and the unstable
distribution (sid), stunnel4 is compiled with stack smashing protection
enabled, which should help protect against arbitrary code execution.";
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
    script_id(892664);
    script_version("$Revision: 39 $");
    script_cve_id("CVE-2013-1762");
    script_name("Debian Security Advisory DSA 2664-1 (stunnel4 - buffer overflow");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-11-04 12:37:28 +0100 (Mo, 04. Nov 2013) $");
    script_tag(name: "creation_date", value:"2013-05-02 00:00:00 +0200 (Do, 02 Mai 2013)");
    script_tag(name: "cvss_base", value:"6.6");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:C");
    script_tag(name: "risk_factor", value:"High");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2664.html");

    script_summary("Debian Security Advisory DSA 2664-1 (stunnel4 - buffer overflow)");

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
if ((res = isdpkgvuln(pkg:"stunnel", ver:"3:4.29-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"stunnel4", ver:"3:4.29-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"stunnel4", ver:"3:4.53-1.1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
