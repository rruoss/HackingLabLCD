# OpenVAS Vulnerability Test
# $Id: deb_483_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 483-1
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
tag_insight = "Two vulnerabilities have been discovered in mysql, a common database
system.  Two scripts contained in the package don't create temporary
files in a secure fashion.  This could allow a local attacker to
overwrite files with the privileges of the user invoking the MySQL
server, which is often the root user.  The Common Vulnerabilities and
Exposures identifies the following problems:

CVE-2004-0381

The script mysqlbug in MySQL allows local users to overwrite
arbitrary files via a symlink attack.

CVE-2004-0388

The script mysqld_multi in MySQL allows local users to overwrite
arbitrary files via a symlink attack.

For the stable distribution (woody) these problems have been fixed in
version 3.23.49-8.6.

For the unstable distribution (sid) these problems will be fixed in
version 4.0.18-6 of mysql-dfsg.

We recommend that you upgrade your mysql, mysql-dfsg and related";
tag_summary = "The remote host is missing an update to mysql
announced via advisory DSA 483-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20483-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53755);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0381", "CVE-2004-0388");
 script_bugtraq_id(9976);
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 483-1 (mysql)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 483-1 (mysql)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"mysql-common", ver:"3.23.49-8.6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient10", ver:"3.23.49-8.6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient10-dev", ver:"3.23.49-8.6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-client", ver:"3.23.49-8.6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server", ver:"3.23.49-8.6", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
