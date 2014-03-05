# OpenVAS Vulnerability Test
# $Id: deb_1573_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1573-1 (rdesktop)
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
tag_insight = "Several remote vulnerabilities have been discovered in rdesktop, a
Remote Desktop Protocol client. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2008-1801

Remote exploitation of an integer underflow vulnerability allows
attackers to execute arbitrary code with the privileges of the
logged-in user.

CVE-2008-1802

Remote exploitation of a BSS overflow vulnerability allows
attackers to execute arbitrary code with the privileges of the
logged-in user.

CVE-2008-1803

Remote exploitation of an integer signedness vulnerability allows
attackers to execute arbitrary code with the privileges of the
logged-in user.


For the stable distribution (etch), these problems have been fixed in
version 1.5.0-1etch2.

For the unstable distribution (sid), these problems have been fixed in
version 1.5.0-4+cvs20071006.

We recommend that you upgrade your rdesktop package.";
tag_summary = "The remote host is missing an update to rdesktop
announced via advisory DSA 1573-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201573-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(61023);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-05-27 15:41:50 +0200 (Tue, 27 May 2008)");
 script_cve_id("CVE-2008-1801", "CVE-2008-1802", "CVE-2008-1803");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1573-1 (rdesktop)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1573-1 (rdesktop)");

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
if ((res = isdpkgvuln(pkg:"rdesktop", ver:"1.5.0-1etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
