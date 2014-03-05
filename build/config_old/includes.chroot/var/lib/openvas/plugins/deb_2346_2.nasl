# OpenVAS Vulnerability Test
# $Id: deb_2346_2.nasl 12 2013-10-27 11:15:33Z jan $
# Description: Auto-generated from advisory DSA 2346-2 (proftpd-dfsg)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The ProFTPD security update, DSA-2346-1, introduced a regression,
preventing successful TLS connections.  This regression does not
affected the stable distribution (squeeze), nor the testing and
unstable distributions.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.3.1-17lenny9.

We recommend that you upgrade your proftpd-dfsg packages.";
tag_summary = "The remote host is missing an update to proftpd-dfsg
announced via advisory DSA 2346-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202346-2";

if(description)
{
 script_id(70560);
 script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-11 02:30:05 -0500 (Sat, 11 Feb 2012)");
 script_name("Debian Security Advisory DSA 2346-2 (proftpd-dfsg)");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
 script_description(desc);

 script_summary("Debian Security Advisory DSA 2346-2 (proftpd-dfsg)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
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
if((res = isdpkgvuln(pkg:"proftpd", ver:"1.3.1-17lenny9", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"proftpd-basic", ver:"1.3.1-17lenny9", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"proftpd-doc", ver:"1.3.1-17lenny9", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"proftpd-mod-ldap", ver:"1.3.1-17lenny9", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"proftpd-mod-mysql", ver:"1.3.1-17lenny9", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"proftpd-mod-pgsql", ver:"1.3.1-17lenny9", rls:"DEB5.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
