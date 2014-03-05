# OpenVAS Vulnerability Test
# $Id: deb_1540_2.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1540-2 (lighttpd)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "It was discovered that lighttpd, a fast webserver with minimal memory
footprint, was didn't correctly handle SSL errors.  This could allow
a remote attacker to disconnect all active SSL connections.

This security update fixes a regression in the previous one, which caused
SSL failures.

For the stable distribution (etch), this problem has been fixed in version
1.4.13-4etch8.

We recommend that you upgrade your lighttpd package.";
tag_summary = "The remote host is missing an update to lighttpd
announced via advisory DSA 1540-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201540-2";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(60793);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-04-21 20:40:14 +0200 (Mon, 21 Apr 2008)");
 script_cve_id("CVE-2008-1531");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1540-2 (lighttpd)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1540-2 (lighttpd)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.13-4etch8", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.13-4etch8", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.13-4etch8", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.13-4etch8", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.13-4etch8", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.13-4etch8", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.13-4etch8", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}