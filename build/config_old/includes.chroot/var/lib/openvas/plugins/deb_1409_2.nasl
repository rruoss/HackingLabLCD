# OpenVAS Vulnerability Test
# $Id: deb_1409_2.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1409-2
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
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
tag_insight = "The previous security update for samba introduced regressions in
the handling of the depreciated filesystem smbfs.  This update fixes
the regression(s) whilst still fixing the security problems.
The original text is reproduced below:

Several local/remote vulnerabilities have been discovered in samba,
a LanManager-like file and printer server for Unix. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-5398

Alin Rad Pop of Secunia Research discovered that nmbd did not properly
check the length of netbios packets. When samba is configured as a WINS
server, a remote attacker could send multiple crafted requests resulting
in the execution of arbitrary code with root privileges.

CVE-2007-4572
Samba developers discovered that nmbd could be made to overrun a buffer
during the processing of GETDC logon server requests.  When samba is
configured as a Primary or Backup Domain Controller, a remote attacker
could send malicious logon requests and possibly cause a denial of
service.

For the stable distribution (etch), these problems have been fixed in
version 3.0.24-6etch7.

For the old stable distribution (sarge), these problems have been fixed in
version 3.0.14a-3sarge9.

For the unstable distribution (sid), these problems have been fixed in
version 3.0.27-1.

We recommend that you upgrade your samba packages.";
tag_summary = "The remote host is missing an update to samba
announced via advisory DSA 1409-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201409-2";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(59637);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:23:47 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-4572", "CVE-2007-5398");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1409-2 (samba)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1409-2 (samba)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"samba-doc", ver:"3.0.14a-3sarge8", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient", ver:"3.0.14a-3sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swat", ver:"3.0.14a-3sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"3.0.14a-3sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-smbpass", ver:"3.0.14a-3sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbfs", ver:"3.0.14a-3sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-dbg", ver:"3.0.14a-3sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-common", ver:"3.0.14a-3sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.3-samba", ver:"3.0.14a-3sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbclient", ver:"3.0.14a-3sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba", ver:"3.0.14a-3sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"winbind", ver:"3.0.14a-3sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"3.0.24-6etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc", ver:"3.0.24-6etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient", ver:"3.0.24-6etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"winbind", ver:"3.0.24-6etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbclient", ver:"3.0.24-6etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbfs", ver:"3.0.24-6etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"3.0.24-6etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-smbpass", ver:"3.0.24-6etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-common", ver:"3.0.24-6etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba", ver:"3.0.24-6etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-samba", ver:"3.0.24-6etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swat", ver:"3.0.24-6etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-dbg", ver:"3.0.24-6etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
