# OpenVAS Vulnerability Test
# $Id: ubuntu_776_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-776-1 (kvm)
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
  kvm                             1:62+dfsg-0ubuntu8.1

Ubuntu 8.10:
  kvm                             1:72+dfsg-1ubuntu6.1

After a standard system upgrade you need to restart all KVM VMs to effect
the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-776-1";

tag_insight = "Avi Kivity discovered that KVM did not correctly handle certain disk
formats.  A local attacker could attach a malicious partition that
would allow the guest VM to read files on the VM host. (CVE-2008-1945,
CVE-2008-2004)

Alfredo Ortega discovered that KVM's VNC protocol handler did not
correctly validate certain messages.  A remote attacker could send
specially crafted VNC messages that would cause KVM to consume CPU
resources, leading to a denial of service. (CVE-2008-2382)

Jan Niehusmann discovered that KVM's Cirrus VGA implementation over VNC
did not correctly handle certain bitblt operations.  A local attacker
could exploit this flaw to potentially execute arbitrary code on the VM
host or crash KVM, leading to a denial of service. (CVE-2008-4539)

It was discovered that KVM's VNC password checks did not use the correct
length.  A remote attacker could exploit this flaw to cause KVM to crash,
leading to a denial of service. (CVE-2008-5714)";
tag_summary = "The remote host is missing an update to kvm
announced via advisory USN-776-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63998);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-20 00:17:15 +0200 (Wed, 20 May 2009)");
 script_cve_id("CVE-2008-1945", "CVE-2008-2004", "CVE-2008-2382", "CVE-2008-4539", "CVE-2008-5714");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_tag(name:"risk_factor", value:"High");
 script_name("Ubuntu USN-776-1 (kvm)");


 script_description(desc);

 script_summary("Ubuntu USN-776-1 (kvm)");

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
if ((res = isdpkgvuln(pkg:"kvm-source", ver:"62+dfsg-0ubuntu8.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kvm", ver:"62+dfsg-0ubuntu8.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kvm-source", ver:"72+dfsg-1ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kvm", ver:"72+dfsg-1ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
