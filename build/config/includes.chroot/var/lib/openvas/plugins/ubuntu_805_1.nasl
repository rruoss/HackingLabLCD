# OpenVAS Vulnerability Test
# $Id: ubuntu_805_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-805-1 (ruby1.9)
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
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  libruby1.8                      1.8.4-1ubuntu1.7
  ruby1.8                         1.8.4-1ubuntu1.7

Ubuntu 8.04 LTS:
  libruby1.8                      1.8.6.111-2ubuntu1.3
  ruby1.8                         1.8.6.111-2ubuntu1.3

Ubuntu 8.10:
  libruby1.8                      1.8.7.72-1ubuntu0.2
  libruby1.9                      1.9.0.2-7ubuntu1.2
  ruby1.8                         1.8.7.72-1ubuntu0.2
  ruby1.9                         1.9.0.2-7ubuntu1.2

Ubuntu 9.04:
  libruby1.8                      1.8.7.72-3ubuntu0.1
  libruby1.9                      1.9.0.2-9ubuntu1.1
  ruby1.8                         1.8.7.72-3ubuntu0.1
  ruby1.9                         1.9.0.2-9ubuntu1.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-805-1";

tag_insight = "It was discovered that Ruby did not properly validate certificates. An
attacker could exploit this and present invalid or revoked X.509
certificates. (CVE-2009-0642)

It was discovered that Ruby did not properly handle string arguments that
represent large numbers. An attacker could exploit this and cause a denial
of service. (CVE-2009-1904)";
tag_summary = "The remote host is missing an update to ruby1.9
announced via advisory USN-805-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64486);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2009-0642", "CVE-2009-1904", "CVE-2009-1892", "CVE-2009-1391", "CVE-2009-1189", "CVE-2007-0062", "CVE-2008-5616", "CVE-2009-0159", "CVE-2009-1252", "CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2464", "CVE-2009-2465", "CVE-2009-2466", "CVE-2009-2467", "CVE-2009-2469", "CVE-2009-2472");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Ubuntu USN-805-1 (ruby1.9)");


 script_description(desc);

 script_summary("Ubuntu USN-805-1 (ruby1.9)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"irb1.8", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rdoc1.8", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbm-ruby1.8", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdbm-ruby1.8", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenssl-ruby1.8", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libreadline-ruby1.8", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.4-1ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irb1.8", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rdoc1.8", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbm-ruby1.8", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdbm-ruby1.8", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenssl-ruby1.8", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libreadline-ruby1.8", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.6.111-2ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irb1.8", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rdoc1.8", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irb1.9", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rdoc1.9", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ri1.9", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.9-elisp", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.9-examples", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.9-dbg", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.9", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.9-dev", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.9", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbm-ruby1.8", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdbm-ruby1.8", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenssl-ruby1.8", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libreadline-ruby1.8", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.7.72-1ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbm-ruby1.9", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdbm-ruby1.9", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenssl-ruby1.9", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libreadline-ruby1.9", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.9", ver:"1.9.0.2-7ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irb1.8", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rdoc1.8", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irb1.9", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rdoc1.9", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ri1.9", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.9-elisp", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.9-examples", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.9-dbg", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.9", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.9-dev", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.9", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbm-ruby1.8", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdbm-ruby1.8", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenssl-ruby1.8", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libreadline-ruby1.8", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.7.72-3ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbm-ruby1.9", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdbm-ruby1.9", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenssl-ruby1.9", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libreadline-ruby1.9", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.9", ver:"1.9.0.2-9ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-1-doc", ver:"1.2.1-5+lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.2.1-5+lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-1-utils", ver:"1.0.2-1+etch3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus", ver:"1.2.1-5+lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-dev", ver:"1.2.1-5+lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-x11", ver:"1.2.1-5+lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dev", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-dev", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dom-inspector", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-venkman", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dom-inspector", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-gnome-support", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-dom-inspector", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-gnome-support", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-venkman", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dom-inspector", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-venkman", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dev", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-gnome-support", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dev", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dev", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-dev", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dom-inspector", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-venkman", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dom-inspector", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-gnome-support", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-dom-inspector", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-gnome-support", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-venkman", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dom-inspector", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.8.10.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-venkman", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.8.10.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser-3.0-branding", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-branding", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dev", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-gnome-support", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.12+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dev", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.8.10.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.8.10.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.8.10.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.8.10.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dev", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-dev", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dom-inspector", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-venkman", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dom-inspector", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-gnome-support", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-dom-inspector", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-gnome-support", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-venkman", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dom-inspector", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-venkman", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser-3.0-branding", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-branding", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dev", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-gnome-support", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dev", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.12+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
