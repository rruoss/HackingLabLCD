###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for thunderbird RHSA-2010:0812-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Mozilla Thunderbird is a standalone mail and newsgroup client.

  A race condition flaw was found in the way Thunderbird handled Document
  Object Model (DOM) element properties. An HTML mail message containing
  malicious content could cause Thunderbird to crash or, potentially, execute
  arbitrary code with the privileges of the user running Thunderbird.
  (CVE-2010-3765)

  Note: JavaScript support is disabled by default in Thunderbird. The
  CVE-2010-3765 issue is not exploitable unless JavaScript is enabled.

  All Thunderbird users should upgrade to this updated package, which
  resolves this issue. All running instances of Thunderbird must be restarted
  for the update to take effect.";

tag_affected = "thunderbird on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-October/msg00035.html");
  script_id(870348);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-04 12:09:38 +0100 (Thu, 04 Nov 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "RHSA", value: "2010:0812-01");
  script_cve_id("CVE-2010-3765");
  script_name("RedHat Update for thunderbird RHSA-2010:0812-01");

  script_description(desc);
  script_summary("Check for the Version of thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~1.5.0.12~33.el4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~1.5.0.12~33.el4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
