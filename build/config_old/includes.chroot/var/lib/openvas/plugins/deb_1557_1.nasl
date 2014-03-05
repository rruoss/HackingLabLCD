# OpenVAS Vulnerability Test
# $Id: deb_1557_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1557-1 (phpmyadmin)
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
tag_insight = "Several remote vulnerabilities have been discovered in phpMyAdmin,
an application to administrate MySQL over the WWW. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-1924

Attackers with CREATE table permissions were allowed to read
arbitrary files readable by the webserver via a crafted
HTTP POST request.

CVE-2008-1567

The PHP session data file stored the username and password of
a logged in user, which in some setups can be read by a local
user.

CVE-2008-1149

Cross site scripting and SQL injection were possible by attackers
that had permission to create cookies in the same cookie domain
as phpMyAdmin runs in.

For the stable distribution (etch), these problems have been fixed in
version 4:2.9.1.1-7.

For the unstable distribution (sid), these problems have been fixed in
version 4:2.11.5.2-1.

We recommend that you upgrade your phpmyadmin package.";
tag_summary = "The remote host is missing an update to phpmyadmin
announced via advisory DSA 1557-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201557-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(60860);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-04-30 19:28:13 +0200 (Wed, 30 Apr 2008)");
 script_cve_id("CVE-2008-1149", "CVE-2008-1567", "CVE-2008-1924");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1557-1 (phpmyadmin)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1557-1 (phpmyadmin)");

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
if ((res = isdpkgvuln(pkg:"phpmyadmin", ver:"2.9.1.1-7", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
