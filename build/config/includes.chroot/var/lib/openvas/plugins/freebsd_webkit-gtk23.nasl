#
#VID 35ecdcbe-3501-11e0-afcd-0015f2db7bde
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 35ecdcbe-3501-11e0-afcd-0015f2db7bde
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
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
tag_insight = "The following package is affected: webkit-gtk2

CVE-2010-2901
The rendering implementation in Google Chrome before 5.0.375.125
allows remote attackers to cause a denial of service (memory
corruption) or possibly have unspecified other impact via unknown
vectors.

CVE-2010-4040
Google Chrome before 7.0.517.41 does not properly handle animated GIF
images, which allows remote attackers to cause a denial of service
(memory corruption) or possibly have unspecified other impact via a
crafted image.

CVE-2010-4042
Google Chrome before 7.0.517.41 does not properly handle element maps,
which allows remote attackers to cause a denial of service or possibly
have unspecified other impact via vectors related to 'stale elements.'

CVE-2010-4199
Google Chrome before 7.0.517.44 does not properly perform a cast of an
unspecified variable during processing of an SVG use element, which
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via a crafted SVG document.

CVE-2010-4492
Use-after-free vulnerability in Google Chrome before 8.0.552.215
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving SVG animations.

CVE-2010-4493
Use-after-free vulnerability in Google Chrome before 8.0.552.215
allows remote attackers to cause a denial of service via vectors
related to the handling of mouse dragging events.

CVE-2010-4578
Google Chrome before 8.0.552.224 and Chrome OS before 8.0.552.343 do
not properly perform cursor handling, which allows remote attackers to
cause a denial of service or possibly have unspecified other impact
via unknown vectors that lead to 'stale pointers.'

CVE-2011-0482
Google Chrome before 8.0.552.237 and Chrome OS before 8.0.552.344 do
not properly perform a cast of an unspecified variable during handling
of anchors, which allows remote attackers to cause a denial of service
or possibly have unspecified other impact via a crafted HTML document.

CVE-2011-0778
Google Chrome before 9.0.597.84 does not properly restrict drag and
drop operations, which might allow remote attackers to bypass the Same
Origin Policy via unspecified vectors.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://bugs.webkit.org/show_bug.cgi?id=48328
https://bugs.webkit.org/show_bug.cgi?id=50710
https://bugs.webkit.org/show_bug.cgi?id=50840
https://bugs.webkit.org/show_bug.cgi?id=50932
https://bugs.webkit.org/show_bug.cgi?id=51993
https://bugs.webkit.org/show_bug.cgi?id=53265
https://bugs.webkit.org/show_bug.cgi?id=53276
http://permalink.gmane.org/gmane.os.opendarwin.webkit.gtk/405
http://www.vuxml.org/freebsd/35ecdcbe-3501-11e0-afcd-0015f2db7bde.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(68950);
 script_version("$Revision: 13 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-2901", "CVE-2010-4040", "CVE-2010-4042", "CVE-2010-4199", "CVE-2010-4492", "CVE-2010-4493", "CVE-2010-4578", "CVE-2011-0482", "CVE-2011-0778");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("FreeBSD Ports: webkit-gtk2");


 script_description(desc);

 script_summary("FreeBSD Ports: webkit-gtk2");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"webkit-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.7")<0) {
    txt += 'Package webkit-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
