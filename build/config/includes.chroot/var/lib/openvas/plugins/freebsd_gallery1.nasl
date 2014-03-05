#
#VID 5752a0df-60c5-4876-a872-f12f9a02fa05
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from vuxml or freebsd advisories
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: gallery

CVE-2004-1106
Cross-site scripting (XSS) vulnerability in Gallery 1.4.4-pl3 and
earlier allows remote attackers to execute arbitrary web script or
HTML via 'specially formed URLs,' possibly via the include parameter
in index.php.

CVE-2005-0219
Multiple cross-site scripting (XSS) vulnerabilities in Gallery
1.3.4-pl1 allow remote attackers to inject arbitrary web script or
HTML via (1) the index field in add_comment.php, (2) set_albumName,
(3) slide_index, (4) slide_full, (5) slide_loop, (6) slide_pause, (7)
slide_dir fields in slideshow_low.php, or (8) username field in
search.php.

CVE-2005-0220
Cross-site scripting vulnerability in login.php in Gallery 1.4.4-pl2
allows remote attackers to inject arbitrary web script or HTML via the
username field.

CVE-2005-0221
Cross-site scripting (XSS) vulnerability in login.php in Gallery 2.0
Alpha allows remote attackers to inject arbitrary web script or HTML
via the g2_form[subject] field.

CVE-2005-0222
main.php in Gallery 2.0 Alpha allows remote attackers to gain
sensitive information by changing the value of g2_subView parameter,
which reveals the path in an error message.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://gallery.menalto.com/modules.php?op=modload&name=News&file=article&sid=147
http://marc.theaimsgroup.com/?l=bugtraq&m=110608459222364
http://www.vuxml.org/freebsd/5752a0df-60c5-4876-a872-f12f9a02fa05.html";
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
 script_id(53079);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-1106", "CVE-2005-0219", "CVE-2005-0220", "CVE-2005-0221", "CVE-2005-0222");
 script_bugtraq_id(11602);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: gallery");


 script_description(desc);

 script_summary("FreeBSD Ports: gallery");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"gallery");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.4.5")<0) {
    txt += 'Package gallery version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
