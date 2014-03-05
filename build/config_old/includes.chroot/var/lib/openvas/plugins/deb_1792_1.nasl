# OpenVAS Vulnerability Test
# $Id: deb_1792_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1792-1 (drupal6)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Multiple vulnerabilities have been discovered in drupal, a web content
management system.

pod.Edge discovered a cross-site scripting vulnerability due that can be
triggered when some browsers interpret UTF-8 strings as UTF-7 if they
appear before the generated HTML document defines its Content-Type.
This allows a malicious user to execute arbitrary javascript in the
context of the web site if they're allowed to post content.

Moritz Naumann discovered an information disclosure vulnerability.  If
a user is tricked into visiting the site via a specially crafted URL
and then submits a form (such as the search box) from that page, the
information in their form submission may be directed to a third-party
site determined by the URL and thus disclosed to the third party. The
third party site may then execute a cross-site request forgery attack
against the submitted form.

For the stable distribution (lenny), these problems have been fixed in version
6.6-3lenny1.

The old stable distribution (etch) does not contain drupal and is not
affected.

For the unstable distribution (sid), these problems have been fixed in
version 6.11-1

We recommend that you upgrade your drupal6 package.";
tag_summary = "The remote host is missing an update to drupal6
announced via advisory DSA 1792-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201792-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(63957);
 script_cve_id("CVE-2009-1575","CVE-2009-1576");
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-11 20:24:31 +0200 (Mon, 11 May 2009)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1792-1 (drupal6)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1792-1 (drupal6)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"drupal6", ver:"6.6-3lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
