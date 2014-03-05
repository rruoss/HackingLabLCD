# OpenVAS Vulnerability Test
# $Id: ubuntu_813_3.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-813-3 (apr-util)
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

Ubuntu 8.04 LTS:
  libaprutil1                     1.2.12+dfsg-3ubuntu0.2

Ubuntu 8.10:
  libaprutil1                     1.2.12+dfsg-7ubuntu0.3

Ubuntu 9.04:
  libaprutil1                     1.2.12+dfsg-8ubuntu0.3

After a standard system upgrade you need to restart any applications using
apr-util, such as Subversion and Apache, to effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-813-3";

tag_insight = "USN-813-1 fixed vulnerabilities in apr. This update provides the corresponding updates for apr-util.

Original advisory details:

 Matt Lewis discovered that apr did not properly sanitize its input when
 allocating memory. If an application using apr processed crafted input, a
 remote attacker could cause a denial of service or potentially execute
 arbitrary code as the user invoking the application.";
tag_summary = "The remote host is missing an update to apr-util
announced via advisory USN-813-3.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64650);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_cve_id("CVE-2009-2412");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Ubuntu USN-813-3 (apr-util)");


 script_description(desc);

 script_summary("Ubuntu USN-813-3 (apr-util)");

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
if ((res = isdpkgvuln(pkg:"libaprutil1-dbg", ver:"1.2.12+dfsg-3ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dev", ver:"1.2.12+dfsg-3ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1", ver:"1.2.12+dfsg-3ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dbg", ver:"1.2.12+dfsg-7ubuntu0.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dev", ver:"1.2.12+dfsg-7ubuntu0.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1", ver:"1.2.12+dfsg-7ubuntu0.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dbg", ver:"1.2.12+dfsg-8ubuntu0.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dev", ver:"1.2.12+dfsg-8ubuntu0.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1", ver:"1.2.12+dfsg-8ubuntu0.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
