# OpenVAS Vulnerability Test
# $Id: deb_2280_1.nasl 13 2013-10-27 12:16:33Z jan $
# Description: Auto-generated from advisory DSA 2280-1 (libvirt)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "It was discovered that libvirt, a library for interfacing with different
virtualization systems, is prone to an integer overflow (CVE-2011-2511).
Additionally, the stable version is prone to a denial of service,
because its error reporting is not thread-safe (CVE-2011-1486).

For the stable distribution (squeeze), these problems have been fixed in
version 0.8.3-5+squeeze2.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.4.6-10+lenny2.

For the testing distribution (wheezy), these problems will fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 0.9.2-7).


We recommend that you upgrade your libvirt packages.";
tag_summary = "The remote host is missing an update to libvirt
announced via advisory DSA 2280-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202280-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(69989);
 script_version("$Revision: 13 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_cve_id("CVE-2011-2511", "CVE-2011-1486");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 2280-1 (libvirt)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 2280-1 (libvirt)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libvirt-bin", ver:"0.8.3-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvirt-dev", ver:"0.8.3-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvirt-doc", ver:"0.8.3-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvirt0", ver:"0.8.3-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvirt0-dbg", ver:"0.8.3-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-libvirt", ver:"0.8.3-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvirt-bin", ver:"0.4.6-10+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvirt-dev", ver:"0.4.6-10+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvirt-doc", ver:"0.4.6-10+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvirt0", ver:"0.4.6-10+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvirt0-dbg", ver:"0.4.6-10+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-libvirt", ver:"0.4.6-10+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}