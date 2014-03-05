# OpenVAS Vulnerability Test
# $Id: deb_137_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 137-1
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
tag_insight = "Marcus Meissner and Sebastian Krahmer discovered and fixed a temporary
file vulnerability in the mm shared memory library.  This problem can
be exploited to gain root access to a machine running Apache which is
linked against this library, if shell access to the user ``www-data''
is already available (which could easily be triggered through PHP).

This problem has been fixed in the upstream version 1.2.0 of mm, which
will be uploaded to the unstable Debian distribution while this
advisory is released.  Fixed packages for potato (Debian 2.2) and
woody (Debian 3.0) are linked below.

We recommend that you upgrade your libmm packages immediately.";
tag_summary = "The remote host is missing an update to mm
announced via advisory DSA 137-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20137-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53400);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(5352);
 script_cve_id("CVE-2002-0658");
 script_tag(name:"cvss_base", value:"6.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 137-1 (mm)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 137-1 (mm)");

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
if ((res = isdpkgvuln(pkg:"libmm10", ver:"1.0.11-1.2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmm10-dev", ver:"1.0.11-1.2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmm11", ver:"1.1.3-6.1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmm11-dev", ver:"1.1.3-6.1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
