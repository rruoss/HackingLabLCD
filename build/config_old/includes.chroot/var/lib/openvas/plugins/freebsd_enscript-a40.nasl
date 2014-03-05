#
#VID a1126054-b57c-11dd-8892-0017319806e7
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID a1126054-b57c-11dd-8892-0017319806e7
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
   enscript-a4
   enscript-letter
   enscript-letterdj

CVE-2008-3863
Stack-based buffer overflow in the read_special_escape function in
src/psgen.c in GNU Enscript 1.6.1 and 1.6.4 beta, when the -e (aka
special escapes processing) option is enabled, allows user-assisted
remote attackers to execute arbitrary code via a crafted ASCII file,
related to the setfilename command.
CVE-2008-4306
Unspecified vulnerability in enscript before 1.6.4 in Ubuntu Linux
6.06 LTS, 7.10, 8.04 LTS, and 8.10 has unknown impact and attack
vectors, possibly related to a buffer overflow.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/secunia_research/2008-41/
http://www.vuxml.org/freebsd/a1126054-b57c-11dd-8892-0017319806e7.html";
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
 script_id(61920);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-11-24 23:46:43 +0100 (Mon, 24 Nov 2008)");
 script_cve_id("CVE-2008-3863", "CVE-2008-4306");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("FreeBSD Ports: enscript-a4, enscript-letter, enscript-letterdj");


 script_description(desc);

 script_summary("FreeBSD Ports: enscript-a4, enscript-letter, enscript-letterdj");

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
bver = portver(pkg:"enscript-a4");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4_2")<0) {
    txt += 'Package enscript-a4 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"enscript-letter");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4_2")<0) {
    txt += 'Package enscript-letter version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"enscript-letterdj");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4_2")<0) {
    txt += 'Package enscript-letterdj version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
