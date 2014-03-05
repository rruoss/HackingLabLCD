# OpenVAS Vulnerability Test
# $Id: ubuntu_705_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-705-1 (ntp)
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
  ntp-refclock                    1:4.2.0a+stable-8.1ubuntu6.1
  ntp-simple                      1:4.2.0a+stable-8.1ubuntu6.1

Ubuntu 7.10:
  ntp                             1:4.2.4p0+dfsg-1ubuntu2.1

Ubuntu 8.04 LTS:
  ntp                             1:4.2.4p4+dfsg-3ubuntu2.1

Ubuntu 8.10:
  ntp                             1:4.2.4p4+dfsg-6ubuntu2.2

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-705-1";

tag_summary = "The remote host is missing an update to ntp
announced via advisory USN-705-1.

It was discovered that NTP did not properly perform signature verification.
A remote attacker could exploit this to bypass certificate validation via
a malformed SSL/TLS signature.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63163);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-01-13 22:38:32 +0100 (Tue, 13 Jan 2009)");
 script_cve_id("CVE-2009-0021");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Ubuntu USN-705-1 (ntp)");


 script_description(desc);

 script_summary("Ubuntu USN-705-1 (ntp)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.0a+stable-8.1ubuntu6.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-server", ver:"4.2.0a+stable-8.1ubuntu6.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-simple", ver:"4.2.0a+stable-8.1ubuntu6.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.0a+stable-8.1ubuntu6.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.0a+stable-8.1ubuntu6.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-refclock", ver:"4.2.0a+stable-8.1ubuntu6.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.4p0+dfsg-1ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.4p0+dfsg-1ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.4p0+dfsg-1ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.4p4+dfsg-3ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.4p4+dfsg-3ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.4p4+dfsg-3ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.4p4+dfsg-6ubuntu2.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.4p4+dfsg-6ubuntu2.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.4p4+dfsg-6ubuntu2.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
