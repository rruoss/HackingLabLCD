# OpenVAS Vulnerability Test
# $Id: deb_1948_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1948-1 (ntp)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
tag_insight = "Robin Park and Dmitri Vinokurov discovered that the daemon component of
the ntp package, a reference implementation of the NTP protocol, is
not properly reacting to certain incoming packets.

An unexpected NTP mode 7 packets (MODE_PRIVATE) with spoofed IP data can lead
ntpd to reply with a mode 7 response to the spoofed address.  This may result
in the service playing packet ping-pong with other ntp servers or even itself
which causes CPU usage and excessive disk use due to logging.  An attacker
can use this to conduct denial of service attacks.


For the oldstable distribution (etch), this problem has been fixed in
version 1:4.2.2.p4+dfsg-2etch4.

For the stable distribution (lenny), this problem has been fixed in
version 1:4.2.4p4+dfsg-8lenny3.

For the testing (squeeze) and unstable (sid) distribution, this problem
will be fixed soon.


We recommend that you upgrade your ntp packages.";
tag_summary = "The remote host is missing an update to ntp
announced via advisory DSA 1948-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201948-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(66515);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
 script_cve_id("CVE-2009-3563");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1948-1 (ntp)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1948-1 (ntp)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"ntp-refclock", ver:"4.2.2.p4+dfsg-2etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-simple", ver:"4.2.2.p4+dfsg-2etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.2.p4+dfsg-2etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.2.p4+dfsg-2etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.2.p4+dfsg-2etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.4p4+dfsg-8lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.4p4+dfsg-8lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.4p4+dfsg-8lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
