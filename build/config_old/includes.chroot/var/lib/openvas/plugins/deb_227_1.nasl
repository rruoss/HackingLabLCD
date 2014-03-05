# OpenVAS Vulnerability Test
# $Id: deb_227_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 227-1
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
tag_insight = "The SuSE Security Team reviewed critical parts of openldap2, an
implementation of the Lightweight Directory Access Protocol (LDAP)
version 2 and 3, and found several buffer overflows and other bugs
remote attackers could exploit to gain access on systems running
vulnerable LDAP servers.  In addition to these bugs, various local
exploitable bugs within the OpenLDAP2 libraries have been fixed.

For the current stable distribution (woody) these problems have been
fixed in version 2.0.23-6.3.

The old stable distribution (potato) does not contain OpenLDAP2
packages.

For the unstable distribution (sid) these problems have been fixed in
version 2.0.27-3.

We recommend that you upgrade your openldap2 packages.";
tag_summary = "The remote host is missing an update to openldap2
announced via advisory DSA 227-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20227-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53721);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-1378", "CVE-2002-1379");
 script_bugtraq_id(6328);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 227-1 (openldap2)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 227-1 (openldap2)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"ldap-gateways", ver:"2.0.23-6.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ldap-utils", ver:"2.0.23-6.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libldap2", ver:"2.0.23-6.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libldap2-dev", ver:"2.0.23-6.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"slapd", ver:"2.0.23-6.3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
