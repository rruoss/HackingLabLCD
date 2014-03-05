#
#VID 4593cb09-4c81-11d9-983e-000c6e8f12ef
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
   kdebase
   kdelibs

CVE-2004-1171
KDE 3.2.x and 3.3.0 through 3.3.2, when saving credentials that are
(1) manually entered by the user or (2) created by the SMB protocol
handler, stores those credentials for plaintext in the user's .desktop
file, which may be created with world-readable permissions, which
could allow local users to obtain usernames and passwords for remote
resources such as SMB shares.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.kde.org/info/security/advisory-20041209-1.txt
http://marc.theaimsgroup.com/?l=bugtraq&m=110178786809694
http://www.vuxml.org/freebsd/4593cb09-4c81-11d9-983e-000c6e8f12ef.html";
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
 script_id(52278);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(11866);
 script_cve_id("CVE-2004-1171");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("FreeBSD Ports: kdebase, kdelibs");


 script_description(desc);

 script_summary("FreeBSD Ports: kdebase, kdelibs");

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
bver = portver(pkg:"kdebase");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.0")>=0 && revcomp(a:bver, b:"3.3.1")<=0) {
    txt += 'Package kdebase version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"kdelibs");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.0")>=0 && revcomp(a:bver, b:"3.3.1")<=0) {
    txt += 'Package kdelibs version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_warning(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
