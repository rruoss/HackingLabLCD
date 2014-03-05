# OpenVAS Vulnerability Test
# $Id: deb_423_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 423-1
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
tag_insight = "The IA-64 maintainers fixed several security related bugs in the Linux
kernel 2.4.17 used for the IA-64 architecture, mostly by backporting
fixes from 2.4.18.  The resolved issues are identified by the appropriate
CVE identifiers:

CVE-2003-0001, CVE-2003-0018, CVE-2003-0127, CVE-2003-0461
CVE-2003-0462, CVE-2003-0476, CVE-2003-0501, CVE-2003-0550
CVE-2003-0551, CVE-2003-0552, CVE-2003-0961, CVE-2003-0985

For a more detailed description of the problems addressed,
please visit the referenced security advisory.

For the stable distribution (woody) this problem has been fixed in
version kernel-image-2.4.17-ia64 for the ia64 architecture.  Other
architectures are already or will be fixed separately.

For the unstable distribution (sid) this problem will be fixed soon
with newly uploaded packages.";
tag_summary = "The remote host is missing an update to kernel-image-2.4.17-ia64
announced via advisory DSA 423-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20423-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53122);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0001", "CVE-2003-0018", "CVE-2003-0127", "CVE-2003-0461", "CVE-2003-0462", "CVE-2003-0476", "CVE-2003-0501", "CVE-2003-0550", "CVE-2003-0551", "CVE-2003-0552", "CVE-2003-0961", "CVE-2003-0985");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 423-1 (kernel-image-2.4.17-ia64)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 423-1 (kernel-image-2.4.17-ia64)");

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
if ((res = isdpkgvuln(pkg:"kernel-source-2.4.17-ia64", ver:"011226.15", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.17-ia64", ver:"011226.15", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-itanium", ver:"011226.15", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-itanium-smp", ver:"011226.15", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-mckinley", ver:"011226.15", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-mckinley-smp", ver:"011226.15", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
