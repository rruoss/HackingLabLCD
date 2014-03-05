# OpenVAS Vulnerability Test
# $Id: deb_2204_1.nasl 13 2013-10-27 12:16:33Z jan $
# Description: Auto-generated from advisory DSA 2204-1 (imp4)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Moritz Naumann discovered that imp4, a webmail component for the horde
framework, is prone to cross-site scripting attacks by a lack of input
sanitising of certain fetchmail information.


For the oldstable distribution (lenny), this problem has been fixed in
version 4.2-4lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 4.3.7+debian0-2.1, which was already included in the squeeze
release.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 4.3.7+debian0-2.1.


We recommend that you upgrade your imp4 packages.";
tag_summary = "The remote host is missing an update to imp4
announced via advisory DSA 2204-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202204-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(69340);
 script_version("$Revision: 13 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3695");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 2204-1 (imp4)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 2204-1 (imp4)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"imp4", ver:"4.2-4lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imp4", ver:"4.3.7+debian0-2.1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imp4", ver:"4.3.7+debian0-2.1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}