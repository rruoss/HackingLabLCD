###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for haproxy CESA-2013:1120 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "HAProxy provides high availability, load balancing, and proxying for TCP
and HTTP-based applications.

A flaw was found in the way HAProxy handled requests when the proxy's
configuration ('/etc/haproxy/haproxy.cfg') had certain rules that use the
hdr_ip criterion. A remote attacker could use this flaw to crash HAProxy
instances that use the affected configuration. (CVE-2013-2175)

Red Hat would like to thank HAProxy upstream for reporting this issue.
Upstream acknowledges David Torgerson as the original reporter.

HAProxy is released as a Technology Preview in Red Hat Enterprise Linux 6.
More information about Red Hat Technology Previews is available at
<a  rel='nofollow' href='https://access.redhat.com/support/offerings/techpreview/'>https://access.redhat.com/support/offerings/techpreview/</a>

All users of haproxy are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.";


if(description)
{
  script_id(881772);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-01 18:43:37 +0530 (Thu, 01 Aug 2013)");
  script_cve_id("CVE-2013-2175");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("CentOS Update for haproxy CESA-2013:1120 centos6 ");


  tag_affected = "haproxy on CentOS 6";

  tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  script_description(desc);
  script_xref(name: "CESA", value: "2013:1120");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-July/019884.html");
  script_summary("Check for the Version of haproxy");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~1.4.22~5.el6_4", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
