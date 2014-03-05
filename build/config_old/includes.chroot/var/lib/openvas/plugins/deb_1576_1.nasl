# OpenVAS Vulnerability Test
# $Id: deb_1576_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1576-1 (openssh)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
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
tag_insight = "The recently announced vulnerability in Debian's openssl package
(DSA-1571-1, CVE-2008-0166) indirectly affects OpenSSH.  As a result,
all user and host keys generated using broken versions of the openssl
package must be considered untrustworthy, even after the openssl update
has been applied.

For more information on how to correct and update your system
to correct for weak keys, please visit the referenced security
advisory.

For the stable distribution (etch), these problems have been fixed in
version 4.3p2-9etch1.  Currently, only a subset of all supported
architectures have been built; further updates will be provided when
they become available.

For the unstable distribution (sid) and the testing distribution
(lenny), these problems have been fixed in version 4.7p1-9.

We recommend that you upgrade your openssh packages and take the";
tag_summary = "The remote host is missing an update to openssh
announced via advisory DSA 1576-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201576-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(61029);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-05-27 15:41:50 +0200 (Tue, 27 May 2008)");
 script_cve_id("CVE-2008-0166", "CVE-2008-1483", "CVE-2007-4752");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1576-1 (openssh)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1576-1 (openssh)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"openssh-blacklist", ver:"0.1.1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ssh", ver:"4.3p2-9etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ssh-krb5", ver:"4.3p2-9etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssh-client", ver:"4.3p2-9etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"4.3p2-9etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssh-server", ver:"4.3p2-9etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
