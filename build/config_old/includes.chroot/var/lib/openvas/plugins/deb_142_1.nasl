# OpenVAS Vulnerability Test
# $Id: deb_142_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 142-1
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
tag_insight = "An integer overflow bug has been discovered in the RPC library used by
the OpenAFS database server, which is derived from the SunRPC library.
This bug could be exploited to crash certain OpenAFS servers
(volserver, vlserver, ptserver, buserver) or to obtain unauthorized
root access to a host running one of these processes.  No exploits are
known to exist yet.

This problem has been fixed in version 1.2.3final2-6 for the current
stable distribution (woody) and in version 1.2.6-1 for the unstable
distribution (sid).  Debian 2.2 (potato) is not affected since it
doesn't contain OpenAFS packages.

We recommend that you upgrade your openafs packages.";
tag_summary = "The remote host is missing an update to openafs
announced via advisory DSA 142-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20142-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53404);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-0391");
 script_bugtraq_id(5356);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 142-1 (openafs)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 142-1 (openafs)");

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
if ((res = isdpkgvuln(pkg:"openafs-modules-source", ver:"1.2.3final2-6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenafs-dev", ver:"1.2.3final2-6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-client", ver:"1.2.3final2-6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-dbserver", ver:"1.2.3final2-6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-fileserver", ver:"1.2.3final2-6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-kpasswd", ver:"1.2.3final2-6", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
