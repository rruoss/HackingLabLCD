#
#VID f9e3e60b-e650-11d8-9b0a-000347a4fa7d
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
   png
   linux-png
   firefox
   thunderbird
   linux-mozilla
   linux-mozilla-devel
   mozilla
   mozilla-gtk1
   netscape-communicator
   netscape-navigator
   linux-netscape-communicator
   linux-netscape-navigator
   ko-netscape-navigator-linux
   ko-netscape-communicator-linux
   ja-netscape-communicator-linux
   ja-netscape-navigator-linux
   netscape7
   ja-netscape7
   pt_BR-netscape7
   fr-netscape7
   de-netscape7

CVE-2004-0597
Multiple buffer overflows in libpng 1.2.5 and earlier, as used in
multiple products, allow remote attackers to execute arbitrary code
via malformed PNG images in which (1) the png_handle_tRNS function
does not properly validate the length of transparency chunk (tRNS)
data, or the (2) png_handle_sBIT or (3) png_handle_hIST functions do
not perform sufficient bounds checking.

CVE-2004-0598
The png_handle_iCCP function in libpng 1.2.5 and earlier allows remote
attackers to cause a denial of service (application crash) via a
certain PNG image that triggers a null dereference.

CVE-2004-0599
Multiple integer overflows in the (1) png_read_png in pngread.c or (2)
png_handle_sPLT functions in pngrutil.c or (3) progressive display
image reading capability in libpng 1.2.5 and earlier allow remote
attackers to cause a denial of service (application crash) via a
malformed PNG image.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://scary.beasts.org/security/CESA-2004-001.txt
http://www.osvdb.org/8312
http://www.osvdb.org/8313
http://www.osvdb.org/8314
http://www.osvdb.org/8315
http://www.osvdb.org/8316
http://secunia.com/advisories/12219
http://secunia.com/advisories/12232
http://bugzilla.mozilla.org/show_bug.cgi?id=251381
http://dl.sourceforge.net/sourceforge/libpng/ADVISORY.txt
http://www.securityfocus.com/archive/1/370853
http://www.vuxml.org/freebsd/f9e3e60b-e650-11d8-9b0a-000347a4fa7d.html";
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
 script_id(52422);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("FreeBSD Ports: png");


 script_description(desc);

 script_summary("FreeBSD Ports: png");

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
bver = portver(pkg:"png");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.5_7")<=0) {
    txt += 'Package png version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-png");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.14_3")<=0) {
    txt += 'Package linux-png version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.2")>=0 && revcomp(a:bver, b:"1.2.2")<=0) {
    txt += 'Package linux-png version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.3")<0) {
    txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"0.7.3")<0) {
    txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.2")<0) {
    txt += 'Package linux-mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-mozilla-devel");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.2")<0) {
    txt += 'Package linux-mozilla-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.2,2")<0) {
    txt += 'Package mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.8.a,2")>=0 && revcomp(a:bver, b:"1.8.a2,2")<=0) {
    txt += 'Package mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla-gtk1");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.2")<0) {
    txt += 'Package mozilla-gtk1 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"netscape-communicator");
if(!isnull(bver) && revcomp(a:bver, b:"4.78")<=0) {
    txt += 'Package netscape-communicator version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"netscape-navigator");
if(!isnull(bver) && revcomp(a:bver, b:"4.78")<=0) {
    txt += 'Package netscape-navigator version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-netscape-communicator");
if(!isnull(bver) && revcomp(a:bver, b:"4.8")<=0) {
    txt += 'Package linux-netscape-communicator version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-netscape-navigator");
if(!isnull(bver) && revcomp(a:bver, b:"4.8")<=0) {
    txt += 'Package linux-netscape-navigator version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ko-netscape-navigator-linux");
if(!isnull(bver) && revcomp(a:bver, b:"4.8")<=0) {
    txt += 'Package ko-netscape-navigator-linux version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ko-netscape-communicator-linux");
if(!isnull(bver) && revcomp(a:bver, b:"4.8")<=0) {
    txt += 'Package ko-netscape-communicator-linux version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-netscape-communicator-linux");
if(!isnull(bver) && revcomp(a:bver, b:"4.8")<=0) {
    txt += 'Package ja-netscape-communicator-linux version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-netscape-navigator-linux");
if(!isnull(bver) && revcomp(a:bver, b:"4.8")<=0) {
    txt += 'Package ja-netscape-navigator-linux version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"7.1")<=0) {
    txt += 'Package netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"7.1")<=0) {
    txt += 'Package ja-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pt_BR-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"7.02")<=0) {
    txt += 'Package pt_BR-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"fr-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"7.02")<=0) {
    txt += 'Package fr-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"de-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"7.02")<=0) {
    txt += 'Package de-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
