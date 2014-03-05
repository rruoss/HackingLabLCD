#
#VID d4a358d3-e09a-11dd-a765-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID d4a358d3-e09a-11dd-a765-0030843d3802
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
   nagios
   nagios2

CVE-2008-5027
The Nagios process in (1) Nagios before 3.0.5 and (2) op5 Monitor
before 4.0.1 allows remote authenticated users to bypass authorization
checks, and trigger execution of arbitrary programs by this process,
via an (a) custom form or a (b) browser addon.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/33320
http://www.ubuntu.com/usn/USN-698-1
http://www.nagios.org/development/history/nagios-3x.php
http://www.vuxml.org/freebsd/d4a358d3-e09a-11dd-a765-0030843d3802.html";
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
 script_id(63165);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-01-13 22:38:32 +0100 (Tue, 13 Jan 2009)");
 script_cve_id("CVE-2008-5027");
 script_bugtraq_id(32156);
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: nagios");


 script_description(desc);

 script_summary("FreeBSD Ports: nagios");

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
bver = portver(pkg:"nagios");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.5")<0) {
    txt += 'Package nagios version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"nagios2");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package nagios2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
