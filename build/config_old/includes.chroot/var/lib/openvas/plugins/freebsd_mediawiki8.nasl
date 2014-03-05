#
#VID 7c0fecd6-f42f-11e1-b17b-000c2977ec30
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 7c0fecd6-f42f-11e1-b17b-000c2977ec30
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
tag_insight = "The following package is affected: mediawiki";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://bugzilla.wikimedia.org/show_bug.cgi?id=39700
https://bugzilla.wikimedia.org/show_bug.cgi?id=37587
https://bugzilla.wikimedia.org/show_bug.cgi?id=39180
https://bugzilla.wikimedia.org/show_bug.cgi?id=39824
https://bugzilla.wikimedia.org/show_bug.cgi?id=39184
https://bugzilla.wikimedia.org/show_bug.cgi?id=39823
http://www.vuxml.org/freebsd/7c0fecd6-f42f-11e1-b17b-000c2977ec30.html";
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
 script_id(71871);
 script_cve_id("CVE-2012-4377", "CVE-2012-4378", "CVE-2012-4379", "CVE-2012-4380", "CVE-2012-4381", "CVE-2012-4382");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-09-07 11:47:17 -0400 (Fri, 07 Sep 2012)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: mediawiki");

 script_description(desc);

 script_summary("FreeBSD Ports: mediawiki");

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
vuln = 0;
txt = "";
bver = portver(pkg:"mediawiki");
if(!isnull(bver) && revcomp(a:bver, b:"1.19")>=0 && revcomp(a:bver, b:"1.19.2")<0) {
    txt += "Package mediawiki version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.18")>=0 && revcomp(a:bver, b:"1.18.5")<0) {
    txt += "Package mediawiki version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt + "\n" + desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
