# OpenVAS Vulnerability Test
# $Id: deb_1387_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1387-1
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
tag_insight = "It has been discovered that the original patch for a buffer overflow in
svc_auth_gss.c in the RPCSEC_GSS RPC library in MIT Kerberos 5
(CVE-2007-3999, DSA-1368-1) was insufficient to protect from arbitrary
code execution in some environments.

The old stable distribution (sarge) does not contain a librpcseggss
package.

For the stable distribution (etch), this problem has been fixed in
version 0.14-2etch3.

For the unstable distribution (sid), this problem has been fixed in
version 0.14-4.

We recommend that you upgrade your librpcsecgss package.";
tag_summary = "The remote host is missing an update to librpcsecgss
announced via advisory DSA 1387-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201387-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(58670);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-4743", "CVE-2007-3999");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1387-1 (librpcsecgss)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1387-1 (librpcsecgss)");

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
if ((res = isdpkgvuln(pkg:"librpcsecgss3", ver:"0.14-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"librpcsecgss-dev", ver:"0.14-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
