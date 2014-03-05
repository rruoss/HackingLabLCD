# OpenVAS Vulnerability Test
# $Id: deb_2149_1.nasl 13 2013-10-27 12:16:33Z jan $
# Description: Auto-generated from advisory DSA 2149-1 (dbus)
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
tag_insight = "R�mi Denis-Courmont discovered that dbus, a message bus application,
is not properly limiting the nesting level when examining messages with
extensive nested variants.  This allows an attacker to crash the dbus system
daemon due to a call stack overflow via crafted messages.


For the stable distribution (lenny), this problem has been fixed in
version 1.2.1-5+lenny2.

For the testing distribution (squeeze), this problem has been fixed in
version 1.2.24-4.

For the unstable distribution (sid), this problem has been fixed in
version 1.2.24-4.


We recommend that you upgrade your dbus packages.";
tag_summary = "The remote host is missing an update to dbus
announced via advisory DSA 2149-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202149-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(68987);
 script_version("$Revision: 13 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2010-4352");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 2149-1 (dbus)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 2149-1 (dbus)");

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
if ((res = isdpkgvuln(pkg:"dbus", ver:"1.2.1-5+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-1-doc", ver:"1.2.1-5+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-x11", ver:"1.2.1-5+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.2.1-5+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-dev", ver:"1.2.1-5+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus", ver:"1.2.24-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-1-dbg", ver:"1.2.24-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-1-doc", ver:"1.2.24-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-x11", ver:"1.2.24-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.2.24-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-dev", ver:"1.2.24-4", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
