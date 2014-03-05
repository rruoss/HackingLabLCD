# OpenVAS Vulnerability Test
# $Id: deb_1861_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1861-1 (libxml)
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
tag_insight = "Rauli Kaksonen, Tero Rontti and Jukka Taimisto discovered several
vulnerabilities in libxml, a library for parsing and handling XML data
files, which can lead to denial of service conditions or possibly arbitrary
code execution in the application using the library.  The Common
Vulnerabilities and Exposures project identifies the following problems:

An XML document with specially-crafted Notation or Enumeration attribute
types in a DTD definition leads to the use of a pointers to memory areas
which have already been freed (CVE-2009-2416).

Missing checks for the depth of ELEMENT DTD definitions when parsing
child content can lead to extensive stack-growth due to a function
recursion which can be triggered via a crafted XML document (CVE-2009-2414).


For the oldstable distribution (etch), this problem has been fixed in
version 1.8.17-14+etch1.

The stable (lenny), testing (squeeze) and unstable (sid) distribution
do not contain libxml anymore but libxml2 for which DSA-1859-1 has been
released.


We recommend that you upgrade your libxml packages.";
tag_summary = "The remote host is missing an update to libxml
announced via advisory DSA 1861-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201861-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(64640);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_cve_id("CVE-2009-2416", "CVE-2009-2414");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1861-1 (libxml)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1861-1 (libxml)");

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
if ((res = isdpkgvuln(pkg:"libxml-dev", ver:"1.8.17-14+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxml1", ver:"1.8.17-14+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
