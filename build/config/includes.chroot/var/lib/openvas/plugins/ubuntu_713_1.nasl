# OpenVAS Vulnerability Test
# $Id: ubuntu_713_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-713-1 (openjdk-6)
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

Ubuntu 8.10:
  icedtea6-plugin                 6b12-0ubuntu6.1
  openjdk-6-jdk                   6b12-0ubuntu6.1
  openjdk-6-jre                   6b12-0ubuntu6.1
  openjdk-6-jre-headless          6b12-0ubuntu6.1
  openjdk-6-jre-lib               6b12-0ubuntu6.1

After a standard system upgrade you need to restart any Java applications
to effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-713-1";

tag_insight = "It was discovered that Java did not correctly handle untrusted applets.
If a user were tricked into running a malicious applet, a remote attacker
could gain user privileges, or list directory contents. (CVE-2008-5347,
CVE-2008-5350)

It was discovered that Kerberos authentication and RSA public key
processing were not correctly handled in Java.  A remote attacker
could exploit these flaws to cause a denial of service. (CVE-2008-5348,
CVE-2008-5349)

It was discovered that Java accepted UTF-8 encodings that might be
handled incorrectly by certain applications.  A remote attacker could
bypass string filters, possible leading to other exploits. (CVE-2008-5351)

Overflows were discovered in Java JAR processing.  If a user or
automated system were tricked into processing a malicious JAR file,
a remote attacker could crash the application, leading to a denial of
service. (CVE-2008-5352, CVE-2008-5354)

It was discovered that Java calendar objects were not unserialized safely.
If a user or automated system were tricked into processing a specially
crafted calendar object, a remote attacker could execute arbitrary code
with user privileges. (CVE-2008-5353)

It was discovered that the Java image handling code could lead to memory
corruption.  If a user or automated system were tricked into processing
a specially crafted image, a remote attacker could crash the application,
leading to a denial of service. (CVE-2008-5358, CVE-2008-5359)

It was discovered that temporary files created by Java had predictable
names.  If a user or automated system were tricked into processing a
specially crafted JAR file, a remote attacker could overwrite sensitive
information.  (CVE-2008-5360)";
tag_summary = "The remote host is missing an update to openjdk-6
announced via advisory USN-713-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63308);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-02-02 23:28:24 +0100 (Mon, 02 Feb 2009)");
 script_cve_id("CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Ubuntu USN-713-1 (openjdk-6)");


 script_description(desc);

 script_summary("Ubuntu USN-713-1 (openjdk-6)");

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
if ((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-source-files", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
