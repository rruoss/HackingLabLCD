# OpenVAS Vulnerability Test
# $Id: ubuntu_827_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-827-1 (dnsmasq)
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
  dnsmasq-base                    2.41-2ubuntu2.2

Ubuntu 8.10:
  dnsmasq-base                    2.45-1ubuntu1.1

Ubuntu 9.04:
  dnsmasq-base                    2.47-3ubuntu0.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-827-1";

tag_insight = "IvAin Arce, Pablo HernAin Jorge, Alejandro Pablo Rodriguez, MartA�n Coco,
Alberto SoliAto Testa and Pablo Annetta discovered that Dnsmasq did not
properly validate its input when processing TFTP requests for files with
long names. A remote attacker could cause a denial of service or execute
arbitrary code with user privileges. Dnsmasq runs as the 'dnsmasq' user by
default on Ubuntu. (CVE-2009-2957)

Steve Grubb discovered that Dnsmasq could be made to dereference a NULL
pointer when processing certain TFTP requests. A remote attacker could
cause a denial of service by sending a crafted TFTP request.
(CVE-2009-2958)";
tag_summary = "The remote host is missing an update to dnsmasq
announced via advisory USN-827-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64827);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-09 02:15:49 +0200 (Wed, 09 Sep 2009)");
 script_cve_id("CVE-2009-2957", "CVE-2009-2958");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Ubuntu USN-827-1 (dnsmasq)");


 script_description(desc);

 script_summary("Ubuntu USN-827-1 (dnsmasq)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "insight" , value : tag_insight);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"dnsmasq", ver:"2.41-2ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsmasq-base", ver:"2.41-2ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsmasq", ver:"2.45-1ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsmasq-base", ver:"2.45-1ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsmasq", ver:"2.47-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsmasq-base", ver:"2.47-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
