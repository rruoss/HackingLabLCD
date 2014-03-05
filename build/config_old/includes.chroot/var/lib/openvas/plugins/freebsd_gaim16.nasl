#
#VID 3b4a6982-0b24-11da-bc08-0001020eed82
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
   gaim
   ja-gaim
   ko-gaim
   ru-gaim
   kdenetwork
   pl-ekg
   centericq
   pl-gnugadu

CVE-2005-1850
Certain contributed scripts for ekg Gadu Gadu client 1.5 and earlier
create temporary files insecurely, with unknown impact and attack
vectors, a different vulnerability than CVE-2005-1916.

CVE-2005-1851
A certain contributed script for ekg Gadu Gadu client 1.5 and earlier
allows attackers to execute shell commands via unknown attack vectors.

CVE-2005-1852
Multiple integer overflows in libgadu, as used in Kopete in KDE 3.2.3
to 3.4.1, ekg before 1.6rc3, and other packages, allows remote
attackers to cause a denial of service (crash) and possibly execute
arbitrary code via an incoming message.

CVE-2005-2369
Multiple integer signedness errors in libgadu, as used in ekg before
1.6rc2 and other packages, may allow remote attackers to cause a
denial of service or execute arbitrary code.

CVE-2005-2370
Multiple 'memory alignment errors' in libgadu, as used in ekg before
1.6rc2 and other packages, allows remote attackers to cause a denial
of service (bus error) on certain architectures such as SPARC via an
incoming message.

CVE-2005-2448
Multiple 'endianness errors' in libgadu in ekg before 1.6rc2 allow
remote attackers to cause a denial of service (invalid behaviour in
applications) on big-endian systems.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://gaim.sourceforge.net/security/?id=20
http://www.kde.org/info/security/advisory-20050721-1.txt
http://marc.theaimsgroup.com/?l=bugtraq&m=112198499417250
http://www.vuxml.org/freebsd/3b4a6982-0b24-11da-bc08-0001020eed82.html";
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
 script_id(55043);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2005-1850", "CVE-2005-1851", "CVE-2005-1852", "CVE-2005-2369", "CVE-2005-2370", "CVE-2005-2448");
 script_bugtraq_id(14345);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("FreeBSD Ports: gaim, ja-gaim, ko-gaim, ru-gaim");


 script_description(desc);

 script_summary("FreeBSD Ports: gaim, ja-gaim, ko-gaim, ru-gaim");

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
bver = portver(pkg:"gaim");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0")<0) {
    txt += 'Package gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-gaim");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0")<0) {
    txt += 'Package ja-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ko-gaim");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0")<0) {
    txt += 'Package ko-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ru-gaim");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0")<0) {
    txt += 'Package ru-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"kdenetwork");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.2")>0 && revcomp(a:bver, b:"3.4.2")<0) {
    txt += 'Package kdenetwork version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pl-ekg");
if(!isnull(bver) && revcomp(a:bver, b:"1.6r3,1")<0) {
    txt += 'Package pl-ekg version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"centericq");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package centericq version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pl-gnugadu");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package pl-gnugadu version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
