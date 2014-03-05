# OpenVAS Vulnerability Test
# $Id: deb_1044_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1044-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 1.0.4-2sarge6.

For the unstable distribution (sid) these problems have been fixed in
version 1.5.dfsg+1.5.0.2-2.

We recommend that you upgrade your Mozilla Firefox packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201044-1";
tag_summary = "The remote host is missing an update to mozilla-firefox
announced via advisory DSA 1044-1. For details on the issues
addressed by the missing update, please visit the referenced
security advisories.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(56664);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:09:45 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-0293", "CVE-2006-0292", "CVE-2005-4134", "CVE-2006-0296", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1790", "CVE-2006-1740", "CVE-2006-1736", "CVE-2006-1735", "CVE-2006-1734", "CVE-2006-1733", "CVE-2006-1732", "CVE-2006-0749", "CVE-2006-1731", "CVE-2006-1730", "CVE-2006-1729", "CVE-2006-1728", "CVE-2006-1727", "CVE-2006-0748");
 script_bugtraq_id(15773,16476,17516);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1044-1 (mozilla-firefox)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1044-1 (mozilla-firefox)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.0.4-2sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"1.0.4-2sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"1.0.4-2sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
