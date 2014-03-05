# OpenVAS Vulnerability Test
# $Id: deb_1134_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1134-1
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
version 1.0.2-2.sarge1.0.8a.

For the unstable distribution (sid) these problems have been fixed in
version 1.5.0.4-1 and xulrunner 1.5.0.4-1 for galeon and epiphany.

We recommend that you upgrade your Mozilla Thunderbird packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201134-1";
tag_summary = "The remote host is missing an update to mozilla-thunderbird
announced via advisory DSA 1134-1.

Several security related problems have been discovered in Mozilla
which are also present in Mozilla Thunderbird.  For details,
please visit the referenced security advisories.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(57203);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-1942", "CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2777", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2781", "CVE-2006-2782", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787", "CVE-2006-1729", "CVE-2005-0752");
 script_bugtraq_id(18228);
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1134-1 (mozilla-thunderbird)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1134-1 (mozilla-thunderbird)");

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
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.0.2-2.sarge1.0.8a", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.0.2-2.sarge1.0.8a", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.0.2-2.sarge1.0.8a", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-offline", ver:"1.0.2-2.sarge1.0.8a", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.0.2-2.sarge1.0.8a", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
