# OpenVAS Vulnerability Test
# $Id: deb_1125_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1125-1
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
version 4.5.3-6.1sarge1.

For the unstable distribution (sid) these problems have been fixed in
version 4.5.8-1.1.

We recommend that you upgrade your drupal packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201125-1";
tag_summary = "The remote host is missing an update to drupal
announced via advisory DSA 1125-1.

Several remote vulnerabilities have been discovered in the Drupal web site
platform, which may lead to the execution of arbitrary web script. The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2006-2742

A SQL injection vulnerability has been discovered in the count and
from variables of the database interface.

CVE-2006-2743

Multiple file extensions were handled incorrectly if Drupal ran on
Apache with mod_mime enabled.

CVE-2006-2831

A variation of CVE-2006-2743 was adressed as well.

CVE-2006-2832

A Cross-Site-Scripting vulnerability in the upload module has been
discovered.

CVE-2006-2833

A Cross-Site-Scripting vulnerability in the taxonomy module has been
discovered.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(57161);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-2742", "CVE-2006-2743", "CVE-2006-2831", "CVE-2006-2832", "CVE-2006-2833");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1125-1 (drupal)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1125-1 (drupal)");

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
if ((res = isdpkgvuln(pkg:"drupal", ver:"4.5.3-6.1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
