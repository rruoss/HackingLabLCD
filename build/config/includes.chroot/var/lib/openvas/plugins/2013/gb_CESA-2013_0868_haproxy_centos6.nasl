###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for haproxy CESA-2013:0868 centos6
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

  A buffer overflow flaw was found in the way HAProxy handled pipelined HTTP
  requests. A remote attacker could send pipelined HTTP requests that would
  cause HAProxy to crash or, potentially, execute arbitrary code with the
  privileges of the user running HAProxy. This issue only affected systems
  using all of the following combined configuration options: HTTP keep alive
  enabled, HTTP keywords in TCP inspection rules, and request appending
  rules. (CVE-2013-1912)

  Red Hat would like to thank Willy Tarreau of HAProxy upstream for reporting
  this issue. Upstream acknowledges Yves Lafon from the W3C as the original
  reporter.

  HAProxy is released as a Technology Preview in Red Hat Enterprise Linux 6.
  More information about Red Hat Technology Previews is available at
  https://access.redhat.com/support/offerings/techpreview

  All users of haproxy are advised to upgrade to this updated package, which
  contains a backported patch to correct this issue.";


tag_affected = "haproxy on CentOS 6";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
if(description)
{
  script_id(881739);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-31 09:51:21 +0530 (Fri, 31 May 2013)");
  script_cve_id("CVE-2013-1912");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("CentOS Update for haproxy CESA-2013:0868 centos6 ");

  script_description(desc);
  script_xref(name: "CESA", value: "2013:0868");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-May/019749.html");
  script_summary("Check for the Version of haproxy");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
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

  if ((res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~1.4.22~4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
