#
#VID bce1f76d-82d0-11de-88ea-001a4d49522b
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID bce1f76d-82d0-11de-88ea-001a4d49522b
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
   subversion
   subversion-freebsd
   p5-subversion
   py-subversion

CVE-2009-2411
Multiple integer overflows in the libsvn_delta library in Subversion
before 1.5.7, and 1.6.x before 1.6.4, allow remote authenticated users
and remote Subversion servers to execute arbitrary code via an svndiff
stream with large windows that trigger a heap-based buffer overflow, a
related issue to CVE-2009-2412.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://subversion.tigris.org/security/CVE-2009-2411-advisory.txt
http://www.vuxml.org/freebsd/bce1f76d-82d0-11de-88ea-001a4d49522b.html";
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
 script_id(64659);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_cve_id("CVE-2009-2411");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("FreeBSD Ports: subversion, subversion-freebsd, p5-subversion, py-subversion");


 script_description(desc);

 script_summary("FreeBSD Ports: subversion, subversion-freebsd, p5-subversion, py-subversion");

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
bver = portver(pkg:"subversion");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4")<0) {
    txt += 'Package subversion version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"subversion-freebsd");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4")<0) {
    txt += 'Package subversion-freebsd version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"p5-subversion");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4")<0) {
    txt += 'Package p5-subversion version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"py-subversion");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4")<0) {
    txt += 'Package py-subversion version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
