# OpenVAS Vulnerability Test
# $Id: deb_1608_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1608-1 (mysql-dfsg-5.0)
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
tag_insight = "Sergei Golubchik discovered that MySQL, a widely-deployed database
server, did not properly validate optional data or index directory
paths given in a CREATE TABLE statement, nor would it (under proper
conditions) prevent two databases from using the same paths for data
or index files.  This permits an authenticated user with authorization
to create tables in one database to read, write or delete data from
tables subsequently created in other databases, regardless of other
GRANT authorizations.  The Common Vulnerabilities and Exposures
project identifies this weakness as CVE-2008-2079.

For the stable distribution (etch), this problem has been fixed in
version 5.0.32-7etch6.  Note that the fix applied will have the
consequence of disallowing the selection of data or index paths
under the database root, which on a Debian system is /var/lib/mysql;
database administrators needing to control the placement of these
files under that location must do so through other means.

We recommend that you upgrade your mysql-dfsg-5.0 packages.";
tag_summary = "The remote host is missing an update to mysql-dfsg-5.0
announced via advisory DSA 1608-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201608-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(61283);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-07-15 02:29:31 +0200 (Tue, 15 Jul 2008)");
 script_cve_id("CVE-2008-2079");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1608-1 (mysql-dfsg-5.0)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1608-1 (mysql-dfsg-5.0)");

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
if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.32-7etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.32-7etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.32-7etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.32-7etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.32-7etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.32-7etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server-4.1", ver:"5.0.32-7etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.0.32-7etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
