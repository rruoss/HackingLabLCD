#
#VID 486aff57-9ecd-11da-b410-000e0c2e438a
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
tag_insight = "The following package is affected: postgresql

CVE-2005-1409
PostgreSQL 7.3.x through 8.0.x gives public EXECUTE access to certain
character conversion functions, which allows unprivileged users to
call those functions with malicious values, with unknown impact, aka
the 'Character conversion vulnerability.'

CVE-2005-1410
The tsearch2 module in PostgreSQL 7.4 through 8.0.x declares the (1)
dex_init, (2) snb_en_init, (3) snb_ru_init, (4) spell_init, and (5)
syn_init functions as 'internal' even when they do not take an
internal argument, which allows attackers to cause a denial of service
(application crash) and possibly have other impacts via SQL commands
that call other functions that accept internal arguments.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.postgresql.org/about/news.315
http://www.vuxml.org/freebsd/486aff57-9ecd-11da-b410-000e0c2e438a.html";
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
 script_id(56268);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2005-1409", "CVE-2005-1410");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: postgresql");


 script_description(desc);

 script_summary("FreeBSD Ports: postgresql");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"postgresql");
if(!isnull(bver) && revcomp(a:bver, b:"7.2.0")>=0 && revcomp(a:bver, b:"7.2.8")<0) {
    txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.3.0")>=0 && revcomp(a:bver, b:"7.3.10")<0) {
    txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.4.0")>=0 && revcomp(a:bver, b:"7.4.8")<0) {
    txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.0.0")>=0 && revcomp(a:bver, b:"8.0.3")<0) {
    txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
