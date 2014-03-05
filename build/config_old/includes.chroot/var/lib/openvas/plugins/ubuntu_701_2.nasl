# OpenVAS Vulnerability Test
# $Id: ubuntu_701_2.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-701-2 (mozilla-thunderbird)
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
  mozilla-thunderbird             1.5.0.13+1.5.0.15~prepatch080614i-0ubuntu0.6.06.1

After a standard system upgrade you need to restart Thunderbird to effect
the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-701-2";

tag_summary = "The remote host is missing an update to mozilla-thunderbird
announced via advisory USN-701-2.

Several flaws were discovered in the browser engine. If a user had Javascript
enabled, these problems could allow an attacker to crash Thunderbird and
possibly execute arbitrary code with user privileges. (CVE-2008-5500)

Boris Zbarsky discovered that the same-origin check in Thunderbird could be
bypassed by utilizing XBL-bindings. If a user had Javascript enabled, an
attacker could exploit this to read data from other domains. (CVE-2008-5503)

Marius Schilder discovered that Thunderbird did not properly handle redirects
to an outside domain when an XMLHttpRequest was made to a same-origin resource.
When Javascript is enabled, it's possible that sensitive information could be
revealed in the XMLHttpRequest response. (CVE-2008-5506)

Chris Evans discovered that Thunderbird did not properly protect a user's data
when accessing a same-domain Javascript URL that is redirected to an unparsable
Javascript off-site resource. If a user were tricked into opening a malicious
website and had Javascript enabled, an attacker may be able to steal a limited
amount of private data. (CVE-2008-5507)

Chip Salzenberg, Justin Schuh, Tom Cross, and Peter William discovered
Thunderbird did not properly parse URLs when processing certain control
characters. (CVE-2008-5508)

Several flaws were discovered in the Javascript engine. If a user were tricked
into opening a malicious website and had Javascript enabled, an attacker could
exploit this to execute arbitrary Javascript code within the context of another
website or with chrome privileges. (CVE-2008-5511, CVE-2008-5512)";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63160);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-01-13 22:38:32 +0100 (Tue, 13 Jan 2009)");
 script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5511", "CVE-2008-5512");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Ubuntu USN-701-2 (mozilla-thunderbird)");


 script_description(desc);

 script_summary("Ubuntu USN-701-2 (mozilla-thunderbird)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.13+1.5.0.15~prepatch080614i-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.5.0.13+1.5.0.15~prepatch080614i-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.15~prepatch080614i-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.15~prepatch080614i-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
