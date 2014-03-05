#
#VID 39a25a63-eb5c-11de-b650-00215c6a37bb
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 39a25a63-eb5c-11de-b650-00215c6a37bb
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: php5

CVE-2009-3557
The tempnam function in ext/standard/file.c in PHP before 5.2.12 and
5.3.x before 5.3.1 allows context-dependent attackers to bypass
safe_mode restrictions, and create files in group-writable or
world-writable directories, via the dir and prefix arguments.

CVE-2009-3558
The posix_mkfifo function in ext/posix/posix.c in PHP before 5.2.12
and 5.3.x before 5.3.1 allows context-dependent attackers to bypass
open_basedir restrictions, and create FIFO files, via the pathname and
mode arguments, as demonstrated by creating a .htaccess file.

CVE-2009-4017
PHP before 5.2.12 and 5.3.x before 5.3.1 does not restrict the number
of temporary files created when handling a multipart/form-data POST
request, which allows remote attackers to cause a denial of service
(resource exhaustion), and makes it easier for remote attackers to
exploit local file inclusion vulnerabilities, via multiple requests,
related to lack of support for the max_file_uploads directive.

CVE-2009-4142
The htmlspecialchars function in PHP before 5.2.12 does not properly
handle (1) overlong UTF-8 sequences, (2) invalid Shift_JIS sequences,
and (3) invalid EUC-JP sequences, which allows remote attackers to
conduct cross-site scripting (XSS) attacks by placing a crafted byte
sequence before a special character.

CVE-2009-4143
PHP before 5.2.12 does not properly handle session data, which has
unspecified impact and attack vectors related to (1) interrupt
corruption of the SESSION superglobal array and (2) the
session.save_path directive.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.php.net/releases/5_2_12.php
http://www.vuxml.org/freebsd/39a25a63-eb5c-11de-b650-00215c6a37bb.html";
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
 script_id(66610);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
 script_cve_id("CVE-2009-3557", "CVE-2009-3558", "CVE-2009-4017", "CVE-2009-4142", "CVE-2009-4143");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("FreeBSD Ports: php5");


 script_description(desc);

 script_summary("FreeBSD Ports: php5");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.12")<0) {
    txt += 'Package php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
