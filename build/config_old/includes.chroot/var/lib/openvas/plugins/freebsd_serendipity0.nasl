#
#VID 9c133aa0-12bd-11dd-bab7-0016179b2dd5
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
   serendipity
   serendipity-devel

CVE-2008-1385
Cross-site scripting (XSS) vulnerability in the Top Referrers (aka
referrer) plugin in Serendipity (S9Y) before 1.3.1 allows remote
attackers to inject arbitrary web script or HTML via the Referer HTTP
header.
CVE-2008-1386
Multiple cross-site scripting (XSS) vulnerabilities in the installer
in Serendipity (S9Y) 1.3 allow remote attackers to inject arbitrary
web script or HTML via (1) unspecified path fields or (2) the database
host field.  NOTE: the timing window for exploitation of this issue
might be limited.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://int21.de/cve/CVE-2008-1385-s9y.html
http://int21.de/cve/CVE-2008-1386-s9y.html
http://blog.s9y.org/archives/193-Serendipity-1.3.1-released.html
http://www.vuxml.org/freebsd/9c133aa0-12bd-11dd-bab7-0016179b2dd5.html";
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
 script_id(60885);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2008-1385", "CVE-2008-1386");
 script_bugtraq_id(28885);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("FreeBSD Ports: serendipity");


 script_description(desc);

 script_summary("FreeBSD Ports: serendipity");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"serendipity");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.1")<0) {
    txt += 'Package serendipity version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"serendipity-devel");
if(!isnull(bver) && revcomp(a:bver, b:"200804242342")<0) {
    txt += 'Package serendipity-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_warning(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
