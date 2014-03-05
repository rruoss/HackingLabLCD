# OpenVAS Vulnerability Test
# $Id: deb_537_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 537-1
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
tag_insight = "Andres Salomon no ticed a problem in the CGI session management of
Ruby, an object-oriented scripting language.  CGI::Session's FileStore
(and presumably PStore, but not in Debian woody) implementations store
session information insecurely.  They simply create files, ignoring
permission issues.  This can lead an attacker who has also shell
access to the webserver to take over a session.

For the stable distribution (woody) this problem has been fixed in
version 1.6.7-3woody3.

For the unstable and testing distributions (sarge and sid) this
problem has been fixed in version 1.8.1+1.8.2pre1-4.

We recommend that you upgrade your libruby package.";
tag_summary = "The remote host is missing an update to ruby
announced via advisory DSA 537-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20537-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53227);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0755");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 537-1 (ruby)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 537-1 (ruby)");

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
if ((res = isdpkgvuln(pkg:"irb", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby-elisp", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby-examples", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurses-ruby", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbm-ruby", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdbm-ruby", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnkf-ruby", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpty-ruby", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libreadline-ruby", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsdbm-ruby", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsyslog-ruby", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtcltk-ruby", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtk-ruby", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby-dev", ver:"1.6.7-3woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
