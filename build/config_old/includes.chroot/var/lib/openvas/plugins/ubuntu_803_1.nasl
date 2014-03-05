# OpenVAS Vulnerability Test
# $Id: ubuntu_803_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-803-1 (dhcp3)
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
  dhcp3-client                    3.0.3-6ubuntu7.1
  dhcp3-client-udeb               3.0.3-6ubuntu7.1

Ubuntu 8.04 LTS:
  dhcp3-client                    3.0.6.dfsg-1ubuntu9.1
  dhcp3-client-udeb               3.0.6.dfsg-1ubuntu9.1

Ubuntu 8.10:
  dhcp3-client                    3.1.1-1ubuntu2.1
  dhcp3-client-udeb               3.1.1-1ubuntu2.1

Ubuntu 9.04:
  dhcp3-client                    3.1.1-5ubuntu8.1
  dhcp3-client-udeb               3.1.1-5ubuntu8.1

After a standard system upgrade you need to restart any DHCP network
connections utilizing dhclient3 to effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-803-1";

tag_insight = "It was discovered that the DHCP client as included in dhcp3 did not verify
the length of certain option fields when processing a response from an IPv4
dhcp server. If a user running Ubuntu 6.06 LTS or 8.04 LTS connected to a
malicious dhcp server, a remote attacker could cause a denial of service or
execute arbitrary code as the user invoking the program, typically the
'dhcp' user. For users running Ubuntu 8.10 or 9.04, a remote attacker
should only be able to cause a denial of service in the DHCP client. In
Ubuntu 9.04, attackers would also be isolated by the AppArmor dhclient3
profile.";
tag_summary = "The remote host is missing an update to dhcp3
announced via advisory USN-803-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64444);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2009-0692");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Ubuntu USN-803-1 (dhcp3)");


 script_description(desc);

 script_summary("Ubuntu USN-803-1 (dhcp3)");

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
if ((res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.0.3-6ubuntu7.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-common", ver:"3.0.3-6ubuntu7.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-dev", ver:"3.0.3-6ubuntu7.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-server", ver:"3.0.3-6ubuntu7.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-relay", ver:"3.0.3-6ubuntu7.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.0.6.dfsg-1ubuntu9.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-common", ver:"3.0.6.dfsg-1ubuntu9.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-dev", ver:"3.0.6.dfsg-1ubuntu9.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-server", ver:"3.0.6.dfsg-1ubuntu9.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-relay", ver:"3.0.6.dfsg-1ubuntu9.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.1.1-1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-common", ver:"3.1.1-1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-dev", ver:"3.1.1-1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-server", ver:"3.1.1-1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-relay", ver:"3.1.1-1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-server-ldap", ver:"3.1.1-1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp-client", ver:"3.1.1-5ubuntu8.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.1.1-5ubuntu8.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-common", ver:"3.1.1-5ubuntu8.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-dev", ver:"3.1.1-5ubuntu8.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-server", ver:"3.1.1-5ubuntu8.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-relay", ver:"3.1.1-5ubuntu8.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-server-ldap", ver:"3.1.1-5ubuntu8.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
