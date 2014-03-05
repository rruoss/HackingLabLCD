# OpenVAS Vulnerability Test
# $Id: deb_988_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 988-1
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
version 2:1.4.4-8.

For the unstable distribution (sid) these problems have been fixed in
version 2:1.4.6-1.

We recommend that you upgrade your squirrelmail package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20988-1";
tag_summary = "The remote host is missing an update to squirrelmail
announced via advisory DSA 988-1.

Several vulnerabilities have been discovered in Squirrelmail, a
commonly used webmail system.  The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2006-0188

Martijn Brinkers and Ben Maurer found a flaw in webmail.php that
allows remote attackers to inject arbitrary web pages into the right
frame via a URL in the right_frame parameter.

CVE-2006-0195

Martijn Brinkers and Scott Hughes discovered an interpretation
conflict in the MagicHTML filter that allows remote attackers to
conduct cross-site scripting (XSS) attacks via style sheet
specifiers with invalid (1) /* and */ comments, or (2) slashes
inside the url keyword, which is processed by some web browsers
including Internet Explorer.

CVE-2006-0377

Vicente Aguilera of Internet Security Auditors, S.L. discovered a
CRLF injection vulnerability, which allows remote attackers to
inject arbitrary IMAP commands via newline characters in the mailbox
parameter of the sqimap_mailbox_select command, aka IMAP
injection. There's no known way to exploit this yet.

For the old stable distribution (woody) these problems have been fixed in
version 1.2.6-5.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(56394);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-0377", "CVE-2006-0195", "CVE-2006-0188");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 988-1 (squirrelmail)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 988-1 (squirrelmail)");

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
if ((res = isdpkgvuln(pkg:"squirrelmail", ver:"1.2.6-5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squirrelmail", ver:"1.4.4-8", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
