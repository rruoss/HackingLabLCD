# OpenVAS Vulnerability Test
# $Id: ubuntu_848_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-848-1 (zope3)
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
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  zope3                           3.2.1-1ubuntu1.2

Ubuntu 8.04 LTS:
  zope3                           3.3.1-5ubuntu2.2

Ubuntu 8.10:
  zope3                           3.3.1-7ubuntu0.2

Ubuntu 9.04:
  zope3                           3.4.0-0ubuntu3.3

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-848-1";

tag_insight = "It was discovered that the Zope Object Database (ZODB) database server
(ZEO) improperly filtered certain commands when a database is shared among
multiple applications or application instances. A remote attacker could
send malicious commands to the server and execute arbitrary code.
(CVE-2009-0668)

It was discovered that the Zope Object Database (ZODB) database server
(ZEO) did not handle authentication properly when a database is shared
among multiple applications or application instances. A remote attacker
could use this flaw to bypass security restrictions. (CVE-2009-0669)

It was discovered that Zope did not limit the number of new object ids a
client could request. A remote attacker could use this flaw to consume a
huge amount of resources, leading to a denial of service. (No CVE
identifier)";
tag_summary = "The remote host is missing an update to zope3
announced via advisory USN-848-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(66062);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-19 21:50:22 +0200 (Mon, 19 Oct 2009)");
 script_cve_id("CVE-2009-0668", "CVE-2009-0669");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Ubuntu USN-848-1 (zope3)");


 script_description(desc);

 script_summary("Ubuntu USN-848-1 (zope3)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"python-zopeinterface", ver:"3.2.1-1ubuntu1.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3-sandbox", ver:"3.2.1-1ubuntu1.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3-doc", ver:"3.2.1-1ubuntu1.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-zopeinterface", ver:"3.2.1-1ubuntu1.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3", ver:"3.2.1-1ubuntu1.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3-doc", ver:"3.3.1-5ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3-sandbox", ver:"3.3.1-5ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-zopeinterface-dbg", ver:"3.3.1-5ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-zopeinterface", ver:"3.3.1-5ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3-dbg", ver:"3.3.1-5ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3", ver:"3.3.1-5ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3-doc", ver:"3.3.1-7ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3-sandbox", ver:"3.3.1-7ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-zopeinterface-dbg", ver:"3.3.1-7ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-zopeinterface", ver:"3.3.1-7ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3-dbg", ver:"3.3.1-7ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3", ver:"3.3.1-7ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3-doc", ver:"3.4.0-0ubuntu3.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3-sandbox", ver:"3.4.0-0ubuntu3.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-zopeinterface-dbg", ver:"3.4.0-0ubuntu3.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-zopeinterface", ver:"3.4.0-0ubuntu3.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3-dbg", ver:"3.4.0-0ubuntu3.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zope3", ver:"3.4.0-0ubuntu3.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
