#
#VID 927743d4-5ca9-11d9-a9e7-0001020eed82
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
   up-imapproxy
   pop3proxy

CVE-2004-1035
Multiple integer signedness errors in (1) imapcommon.c, (2) main.c,
(3) request.c, and (4) select.c for up-imapproxy IMAP proxy 1.2.2
allow remote attackers to cause a denial of service (server crash) and
possibly leak sensitive information via certain literal values that
are not properly handled when using the IMAP_Line_Read function.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://marc.theaimsgroup.com/?l=bugtraq&m=109995749510773
http://www.vuxml.org/freebsd/927743d4-5ca9-11d9-a9e7-0001020eed82.html";
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
 script_id(52256);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-1035");
 script_bugtraq_id(11630);
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: up-imapproxy");


 script_description(desc);

 script_summary("FreeBSD Ports: up-imapproxy");

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
bver = portver(pkg:"up-imapproxy");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.2")<0) {
    txt += 'Package up-imapproxy version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pop3proxy");
if(!isnull(bver) && revcomp(a:bver, b:"1.1")<=0) {
    txt += 'Package pop3proxy version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
