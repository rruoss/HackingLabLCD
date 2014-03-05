# OpenVAS Vulnerability Test
# $Id: deb_1907_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1907-1 (kvm)
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
tag_insight = "Several vulnerabilities have been discovered in kvm, a full virtualization system.
The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2008-5714

Chris Webb discovered an off-by-one bug limiting KVM's VNC passwords to 7
characters. This flaw might make it easier for remote attackers to guess the VNC
password, which is limited to seven characters where eight was intended.

CVE-2009-3290

It was discovered that the kvm_emulate_hypercall function in KVM does not
prevent access to MMU hypercalls from ring 0, which allows local guest OS users
to cause a denial of service (guest kernel crash) and read or write guest kernel
memory.


For the stable distribution (lenny), these problems have been fixed in version
72+dfsg-5~lenny3.

The oldstable distribution (etch) does not contain kvm.

For the testing distribution (squeeze) these problems will be fixed soon.

For the unstable distribution (sid) these problems have been fixed in version
85+dfsg-4.1


We recommend that you upgrade your kvm packages.";
tag_summary = "The remote host is missing an update to kvm
announced via advisory DSA 1907-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201907-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(66053);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-19 21:50:22 +0200 (Mon, 19 Oct 2009)");
 script_cve_id("CVE-2008-5714", "CVE-2009-3290");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1907-1 (kvm)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1907-1 (kvm)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"kvm-source", ver:"72+dfsg-5~lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kvm", ver:"72+dfsg-5~lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
