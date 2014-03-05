#
#VID ca0841ff-1254-11de-a964-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID ca0841ff-1254-11de-a964-0030843d3802
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
tag_insight = "The following packages are affected:
   proftpd
   proftpd-mysql
   proftpd-devel

CVE-2009-0542
SQL injection vulnerability in ProFTPD Server 1.3.1 through 1.3.2rc2
allows remote attackers to execute arbitrary SQL commands via a '%'
(percent) character in the username, which introduces a ''' (single
quote) character during variable substitution by mod_sql.
CVE-2009-0543
ProFTPD Server 1.3.1, with NLS support enabled, allows remote
attackers to bypass SQL injection protection mechanisms via invalid,
encoded multibyte characters, which are not properly handled in (1)
mod_sql_mysql and (2) mod_sql_postgres.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/33842/
http://bugs.proftpd.org/show_bug.cgi?id=3173
http://bugs.proftpd.org/show_bug.cgi?id=3124
http://milw0rm.com/exploits/8037
http://www.vuxml.org/freebsd/ca0841ff-1254-11de-a964-0030843d3802.html";
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
 script_id(63630);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
 script_cve_id("CVE-2009-0542", "CVE-2009-0543");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: proftpd, proftpd-mysql");


 script_description(desc);

 script_summary("FreeBSD Ports: proftpd, proftpd-mysql");

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
bver = portver(pkg:"proftpd");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.2")<0) {
    txt += 'Package proftpd version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"proftpd-mysql");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.2")<0) {
    txt += 'Package proftpd-mysql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"proftpd-devel");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.20080922")<=0) {
    txt += 'Package proftpd-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
