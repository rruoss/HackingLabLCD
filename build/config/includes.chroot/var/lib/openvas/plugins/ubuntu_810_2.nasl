# OpenVAS Vulnerability Test
# $Id: ubuntu_810_2.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-810-2 (fixed)
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
tag_summary = "The remote host is missing an update to fixed
announced via advisory USN-810-2.

Original advisory details:

 Moxie Marlinspike discovered that NSS did not properly handle regular
 expressions in certificate names. A remote attacker could create a
 specially crafted certificate to cause a denial of service (via application
 crash) or execute arbitrary code as the user invoking the program.
 (CVE-2009-2404)
 
 Moxie Marlinspike and Dan Kaminsky independently discovered that NSS did
 not properly handle certificates with NULL characters in the certificate
 name. An attacker could exploit this to perform a man in the middle attack
 to view sensitive information or alter encrypted communications.
 (CVE-2009-2408)
 
 Dan Kaminsky discovered NSS would still accept certificates with MD2 hash
 signatures. As a result, an attacker could potentially create a malicious
 trusted certificate to impersonate another site. (CVE-2009-2409)";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=USN-810-2";
                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(64574);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2409");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Ubuntu USN-810-2 (fixed)");


 script_description(desc);

 script_summary("Ubuntu USN-810-2 (fixed)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "login/SSH/success", "ssh/login/packages");
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
if ((res = isdpkgvuln(pkg:"libnspr4-0d-dbg", ver:"4.7.5-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-0d", ver:"4.7.5-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-dev", ver:"4.7.5-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-0d-dbg", ver:"4.7.5-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-0d", ver:"4.7.5-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-dev", ver:"4.7.5-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-0d-dbg", ver:"4.7.5-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-0d", ver:"4.7.5-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-dev", ver:"4.7.5-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
