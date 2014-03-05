#
#VID d3921810-3c80-11e1-97e8-00215c6a37bb
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID d3921810-3c80-11e1-97e8-00215c6a37bb
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
   php5
   php5-exif
   php52
   php52-exif

CVE-2011-4566
Integer overflow in the exif_process_IFD_TAG function in exif.c in the
exif extension in PHP 5.4.0beta2 on 32-bit platforms allows remote
attackers to read the contents of arbitrary memory locations or cause
a denial of service via a crafted offset_val value in an EXIF header
in a JPEG file, a different vulnerability than CVE-2011-0708.

CVE-2011-4885
PHP before 5.3.9 computes hash values for form parameters without
restricting the ability to trigger hash collisions predictably, which
allows remote attackers to cause a denial of service (CPU consumption)
by sending many crafted parameters.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.nruns.com/_downloads/advisory28122011.pdf
http://www.vuxml.org/freebsd/d3921810-3c80-11e1-97e8-00215c6a37bb.html";
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
 script_id(70759);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
 script_cve_id("CVE-2011-4566", "CVE-2011-4885");
 script_tag(name:"risk_factor", value:"High");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)");
 script_name("FreeBSD Ports: php5, php5-exif");


 script_description(desc);

 script_summary("FreeBSD Ports: php5, php5-exif");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
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
txt = "";
bver = portver(pkg:"php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.3.9")<0) {
    txt += 'Package php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-exif");
if(!isnull(bver) && revcomp(a:bver, b:"5.3.9")<0) {
    txt += 'Package php5-exif version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php52");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.17_5")<0) {
    txt += 'Package php52 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php52-exif");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.17_6")<0) {
    txt += 'Package php52-exif version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
