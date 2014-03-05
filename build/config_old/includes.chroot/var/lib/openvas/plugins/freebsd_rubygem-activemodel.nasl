#
#VID 748aa89f-d529-11e1-82ab-001fd0af1a4c
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 748aa89f-d529-11e1-82ab-001fd0af1a4c
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
tag_insight = "The following package is affected: rubygem-activemodel

CVE-2012-2660
actionpack/lib/action_dispatch/http/request.rb in Ruby on Rails before
3.0.13, 3.1.x before 3.1.5, and 3.2.x before 3.2.4 does not properly
consider differences in parameter handling between the Active Record
component and the Rack interface, which allows remote attackers to
bypass intended database-query restrictions and perform NULL checks
via a crafted request, as demonstrated by certain '[nil]' values, a
related issue to CVE-2012-2694.
CVE-2012-2661
The Active Record component in Ruby on Rails 3.0.x before 3.0.13,
3.1.x before 3.1.5, and 3.2.x before 3.2.4 does not properly implement
the passing of request data to a where method in an ActiveRecord
class, which allows remote attackers to conduct certain SQL injection
attacks via nested query parameters that leverage unintended
recursion, a related issue to CVE-2012-2695.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://groups.google.com/forum/?fromgroups#!topic/rubyonrails-security/8SA-M3as7A8
https://groups.google.com/forum/?fromgroups#!topic/rubyonrails-security/dUaiOOGWL1k
http://www.vuxml.org/freebsd/748aa89f-d529-11e1-82ab-001fd0af1a4c.html";
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
 script_id(71520);
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_cve_id("CVE-2012-2660", "CVE-2012-2661");
 script_tag(name:"risk_factor", value:"High");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
 script_name("FreeBSD Ports: rubygem-activemodel");

 script_description(desc);

 script_summary("FreeBSD Ports: rubygem-activemodel");

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
bver = portver(pkg:"rubygem-activemodel");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.4")<0) {
    txt += "Package rubygem-activemodel version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt + "\n" + desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
