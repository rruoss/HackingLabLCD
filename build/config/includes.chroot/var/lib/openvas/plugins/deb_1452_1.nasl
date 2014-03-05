# OpenVAS Vulnerability Test
# $Id: deb_1452_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1452-1 (wzdftpd)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
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
tag_insight = "k1tk4t discovered that wzdftpd, a portable, modular, small and efficient
ftp server, did not correctly handle the receipt of long usernames.  This
could allow remote users to cause the daemon to exit.

For the stable distribution (etch), this problem has been fixed in version
0.8.1-2etch1.

For the old stable distribution (sarge), this problem has been fixed in
version 0.5.2-1.1sarge3.

For the unstable distribution (sid), this problem has been fixed in version
0.8.2-2.1.

We recommend that you upgrade your wzdftpd package.";
tag_summary = "The remote host is missing an update to wzdftpd
announced via advisory DSA 1452-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201452-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(60107);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:23:47 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-5300");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1452-1 (wzdftpd)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1452-1 (wzdftpd)");

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
if ((res = isdpkgvuln(pkg:"wzdftpd-dev", ver:"0.5.2-1.1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wzdftpd-mod-perl", ver:"0.5.2-1.1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wzdftpd-back-mysql", ver:"0.5.2-1.1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wzdftpd", ver:"0.5.2-1.1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wzdftpd-mod-tcl", ver:"0.5.2-1.1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wzdftpd-back-mysql", ver:"0.8.1-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wzdftpd-mod-tcl", ver:"0.8.1-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wzdftpd-back-pgsql", ver:"0.8.1-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wzdftpd-mod-avahi", ver:"0.8.1-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wzdftpd-dev", ver:"0.8.1-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wzdftpd", ver:"0.8.1-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wzdftpd-mod-perl", ver:"0.8.1-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
