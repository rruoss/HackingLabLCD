# OpenVAS Vulnerability Test
# $Id: deb_2380_1.nasl 12 2013-10-27 11:15:33Z jan $
# Description: Auto-generated from advisory DSA 2380-1 (foomatic-filters)
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
tag_insight = "It was discovered that the foomatic-filters, a support package for
setting up printers, allowed authenticated users to submit crafted
print jobs which would execute shell commands on the print servers.

CVE-2011-2697 was assigned to the vulnerability in the Perl
implementation included in lenny, and CVE-2011-2964 to the
vulnerability affecting the C reimplementation part of squeeze.

For the oldstable distribution (lenny), this problem has been fixed in
version 3.0.2-20080211-3.2+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 4.0.5-6+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 4.0.9-1.

We recommend that you upgrade your foomatic-filters packages.";
tag_summary = "The remote host is missing an update to foomatic-filters
announced via advisory DSA 2380-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202380-1";

if(description)
{
 script_id(70699);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-2697", "CVE-2011-2964");
 script_tag(name:"risk_factor", value:"High");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-11 03:26:17 -0500 (Sat, 11 Feb 2012)");
 script_name("Debian Security Advisory DSA 2380-1 (foomatic-filters)");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
 script_description(desc);

 script_summary("Debian Security Advisory DSA 2380-1 (foomatic-filters)");

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
if((res = isdpkgvuln(pkg:"foomatic-filters", ver:"3.0.2-20080211-3.2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"foomatic-filters", ver:"4.0.5-6+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"foomatic-filters", ver:"4.0.9-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
