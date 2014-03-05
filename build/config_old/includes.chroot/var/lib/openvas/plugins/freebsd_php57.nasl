#
#VID b2a6fc0e-070f-11e0-a6e9-00215c6a37bb
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID b2a6fc0e-070f-11e0-a6e9-00215c6a37bb
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
   php52

CVE-2010-2950
Format string vulnerability in stream.c in the phar extension in PHP
5.3.x through 5.3.3 allows context-dependent attackers to obtain
sensitive information (memory contents) and possibly execute arbitrary
code via a crafted phar:// URI that is not properly handled by the
phar_stream_flush function, leading to errors in the
php_stream_wrapper_log_error function.  NOTE: this vulnerability exists
because of an incomplete fix for CVE-2010-2094.

CVE-2010-3436
fopen_wrappers.c in PHP 5.3.x through 5.3.3 might allow remote
attackers to bypass open_basedir restrictions via vectors related to
the length of a filename.

CVE-2010-3709
The ZipArchive::getArchiveComment function in PHP 5.2.x through 5.2.14
and 5.3.x through 5.3.3 allows context-dependent attackers to cause a
denial of service (NULL pointer dereference and application crash) via
a crafted ZIP archive.

CVE-2010-4150
Double free vulnerability in the imap_do_open function in the IMAP
extension (ext/imap/php_imap.c) in PHP 5.2 before 5.2.15 and 5.3
before 5.3.4 allows attackers to cause a denial of service (memory
corruption) or possibly execute arbitrary code via unspecified
vectors.";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";

tag_solution = "Update your system with the appropriate patches or
software upgrades.";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(68689);
 script_version("$Revision: 13 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2006-7243", "CVE-2010-2950", "CVE-2010-3436", "CVE-2010-3709", "CVE-2010-4150");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: php5");


 script_description(desc);

 script_summary("FreeBSD Ports: php5");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "insight" , value : tag_insight);
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
bver = portver(pkg:"php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.3.4")<0) {
    txt += 'Package php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php52");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.15")<0) {
    txt += 'Package php52 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
