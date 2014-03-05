#
#VID dca0a345-ed81-11d9-8310-0001020eed82
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
tag_insight = "The following package is affected: wordpress

CVE-2005-2107
Multiple cross-site scripting (XSS) vulnerabilities in post.php in
WordPress 1.5.1.2 and earlier allow remote attackers to inject
arbitrary web script or HTML via the (1) p or (2) comment parameter.

CVE-2005-2108
SQL injection vulnerability in XMLRPC server in WordPress 1.5.1.2 and
earlier allows remote attackers to execute arbitrary SQL commands via
input that is not filtered in the HTTP_RAW_POST_DATA variable, which
stores the data in an XML file.

CVE-2005-2109
wp-login.php in WordPress 1.5.1.2 and earlier allows remote attackers
to change the content of the forgotten password e-mail message via the
message variable, which is not initialized before use.

CVE-2005-2110
WordPress 1.5.1.2 and earlier allows remote attackers to obtain
sensitive information via (1) a direct request to menu-header.php or a
'1' value in the feed parameter to (2) wp-atom.php, (3) wp-rss.php, or
(4) wp-rss2.php, which reveal the path in an error message.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://marc.theaimsgroup.com/?l=bugtraq&m=112006967221438
http://www.vuxml.org/freebsd/dca0a345-ed81-11d9-8310-0001020eed82.html";
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
 script_id(54000);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2005-2107", "CVE-2005-2108", "CVE-2005-2109", "CVE-2005-2110");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: wordpress");


 script_description(desc);

 script_summary("FreeBSD Ports: wordpress");

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
bver = portver(pkg:"wordpress");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.1.3,1")<0) {
    txt += 'Package wordpress version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
