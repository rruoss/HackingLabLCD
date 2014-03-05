# OpenVAS Vulnerability Test
# $Id: deb_303_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 303-1
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
tag_insight = "CVE-2003-0073: The mysql package contains a bug whereby dynamically
allocated memory is freed more than once, which could be deliberately
triggered by an attacker to cause a crash, resulting in a denial of
service condition.  In order to exploit this vulnerability, a valid
username and password combination for access to the MySQL server is
required.

CVE-2003-0150: The mysql package contains a bug whereby a malicious
user, granted certain permissions within mysql, could create a
configuration file which would cause the mysql server to run as root,
or any other user, rather than the mysql user.

For the stable distribution (woody) both problems have been fixed in
version 3.23.49-8.4.

The old stable distribution (potato) is only affected by
CVE-2003-0150, and this has been fixed in version 3.22.32-6.4.

For the unstable distribution (sid), CVE-2003-0073 was fixed in
version 4.0.12-2, and CVE-2003-0150 will be fixed soon.

We recommend that you update your mysql package.";
tag_summary = "The remote host is missing an update to mysql
announced via advisory DSA 303-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20303-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53595);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0073", "CVE-2003-0150");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 303-1 (mysql)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 303-1 (mysql)");

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
if ((res = isdpkgvuln(pkg:"mysql-common", ver:"3.23.49-8.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-doc", ver:"3.23.49-8.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient10", ver:"3.23.49-8.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient10-dev", ver:"3.23.49-8.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-client", ver:"3.23.49-8.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server", ver:"3.23.49-8.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-doc", ver:"3.22.32-6.4", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-client", ver:"3.22.32-6.4", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server", ver:"3.22.32-6.4", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
