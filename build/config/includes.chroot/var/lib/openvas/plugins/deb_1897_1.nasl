# OpenVAS Vulnerability Test
# $Id: deb_1897_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1897-1 (horde3)
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
tag_insight = "Stefan Esser discovered that Horde, a web application framework providing
classes for dealing with preferences, compression, browser detection,
connection tracking, MIME, and more, is insufficiently validating and
escaping user provided input.  The Horde_Form_Type_image form element
allows to reuse a temporary filename on reuploads which are stored in a
hidden HTML field and then trusted without prior validation.  An attacker
can use this to overwrite arbitrary files on the system or to upload PHP
code and thus execute arbitrary code with the rights of the webserver.


For the oldstable distribution (etch), this problem has been fixed in
version 3.1.3-4etch6.

For the stable distribution (lenny), this problem has been fixed in
version 3.2.2+debian0-2+lenny1.

For the testing distribution (squeeze), this problem has been fixed in
version 3.3.5+debian0-1.

For the unstable distribution (sid), this problem has been fixed in
version 3.3.5+debian0-1.


We recommend that you upgrade your horde3 packages.";
tag_summary = "The remote host is missing an update to horde3
announced via advisory DSA 1897-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201897-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(65002);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-06 02:49:40 +0200 (Tue, 06 Oct 2009)");
 script_cve_id("CVE-2009-3236");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1897-1 (horde3)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1897-1 (horde3)");

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
if ((res = isdpkgvuln(pkg:"horde3", ver:"3.1.3-4etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"horde3", ver:"3.2.2+debian0-2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
