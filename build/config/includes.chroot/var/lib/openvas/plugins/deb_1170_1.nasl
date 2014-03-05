# OpenVAS Vulnerability Test
# $Id: deb_1170_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1170-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
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
tag_solution = "For the stable distribution (sarge) this problem has been fixed in
version 3.4.3-13sarge1.

For the unstable distribution (sid) this problem has been fixed in
version 4.1.1-11.

We recommend that you upgrade your fastjar package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201170-1";
tag_summary = "The remote host is missing an update to gcc-3.4
announced via advisory DSA 1170-1.

J�rgen Weigert discovered that upon unpacking JAR archives fastjar
from the GNU Compiler Collection does not check the path for included
files and allows to create or overwrite files in upper directories.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(57338);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-3619");
 script_bugtraq_id(15669);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1170-1 (gcc-3.4)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1170-1 (gcc-3.4)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"cpp-3.4-doc", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"g77-3.4-doc", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gcc-3.4-doc", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnat-3.4-doc", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gpc-2.1-3.4-doc", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcj5-common", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libstdc++6-doc", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cpp-3.4", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fastjar", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"g++-3.4", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"g77-3.4", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gcc-3.4", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gcc-3.4-base", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gcj-3.4", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gij-3.4", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnat-3.4", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gobjc-3.4", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gpc-2.1-3.4", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libffi3", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libffi3-dev", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcc1", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcj5", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcj5-awt", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcj5-dev", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libstdc++6", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libstdc++6-dbg", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libstdc++6-dev", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libstdc++6-pic", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"treelang-3.4", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lib32gcc1", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lib32stdc++6", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnat-3.4", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libstdc++6-0", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libstdc++6-0-dbg", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libstdc++6-0-dev", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libstdc++6-0-pic", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gcc-3.4-hppa64", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgcc2", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lib64gcc1", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lib64stdc++6", ver:"3.4.3-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
