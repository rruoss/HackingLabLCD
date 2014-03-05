#
#VID 79630c0c-8dcc-45d0-9908-4087fe1d618c
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
tag_insight = "The following packages are affected:
   squirrelmail
   ja-squirrelmail

CVE-2004-1036
Cross-site scripting (XSS) vulnerability in the decoding of encoded
text in certain headers in mime.php for SquirrelMail 1.4.3a and
earlier, and 1.5.1-cvs before 23rd October 2004, allows remote
attackers to execute arbitrary web script or HTML.

CVE-2005-0075
prefs.php in SquirrelMail before 1.4.4, with register_globals enabled,
allows remote attackers to inject local code into the SquirrelMail
code via custom preference handlers.

CVE-2005-0103
PHP remote code injection vulnerability in webmail.php in SquirrelMail
before 1.4.4 allows remote attackers to execute arbitrary PHP code by
modifying a URL parameter to reference a URL on a remote web server
that contains the code.

CVE-2005-0104
Cross-site scripting (XSS) vulnerability in webmail.php in
SquirrelMail before 1.4.4 allows remote attackers to inject arbitrary
web script or HTML via certain integer variables.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.squirrelmail.org/security/issue/2005-01-14
http://www.squirrelmail.org/security/issue/2005-01-19
http://www.squirrelmail.org/security/issue/2005-01-20
http://marc.theaimsgroup.com/?l=bugtraq&m=110702772714662
http://www.vuxml.org/freebsd/79630c0c-8dcc-45d0-9908-4087fe1d618c.html";
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
 script_id(52996);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-1036", "CVE-2005-0075", "CVE-2005-0103", "CVE-2005-0104");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: squirrelmail, ja-squirrelmail");


 script_description(desc);

 script_summary("FreeBSD Ports: squirrelmail, ja-squirrelmail");

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
bver = portver(pkg:"squirrelmail");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.4")<0) {
    txt += 'Package squirrelmail version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-squirrelmail");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.4")<0) {
    txt += 'Package ja-squirrelmail version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
