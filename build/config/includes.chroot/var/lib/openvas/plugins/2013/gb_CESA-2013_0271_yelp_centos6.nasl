###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for yelp CESA-2013:0271 centos6 
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
tag_insight = "Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A
  web page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user
  running Firefox. (CVE-2013-0775, CVE-2013-0780, CVE-2013-0782,
  CVE-2013-0783)
  
  It was found that, after canceling a proxy server's authentication
  prompt, the address bar continued to show the requested site's address. An
  attacker could use this flaw to conduct phishing attacks by tricking a
  user into believing they are viewing a trusted site. (CVE-2013-0776)
  
  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Nils, Abhishek Arya, Olli Pettay, Christoph Diehl,
  Gary Kwong, Jesse Ruderman, Andrew McCreight, Joe Drew, Wayne Mery, and
  Michal Zalewski as the original reporters of these issues.
  
  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 17.0.3 ESR. You can find a link to the Mozilla
  advisories in the References section of this erratum.
  
  Note that due to a Kerberos credentials change, the following configuration
  steps may be required when using Firefox 17.0.3 ESR with the Enterprise
  Identity Management (IPA) web interface:
  
  https://access.redhat.com/knowledge/solutions/294303
  
  Important: Firefox 17 is not completely backwards-compatible with all
  Mozilla add-ons and Firefox plug-ins that worked with Firefox 10.0.
  Firefox 17 checks compatibility on first-launch, and, depending on the
  individual configuration and the installed add-ons and plug-ins, may
  disable said Add-ons and plug-ins, or attempt to check for updates and
  upgrade them. Add-ons and plug-ins may have to be manually updated.
  
  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 17.0.3 ESR, which corrects these issues. After installing
  the update, Firefox must be restarted for the changes to take effect.
  
  4. Solution:
  
  Before applying this update, make sure all previously-released errata
  relevant to your system have been applied.
  
  This update is available via the Red Hat Network. Details on how to
  use the Red Hat Network to apply this update are available at
  https://access.redhat.com/knowledge/articles/11258

  Description truncated, for more information please check the Reference URL";


tag_affected = "yelp on CentOS 6";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-February/019248.html");
  script_id(881615);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-22 10:09:03 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "CESA", value: "2013:0271");
  script_name("CentOS Update for yelp CESA-2013:0271 centos6 ");

  script_description(desc);
  script_summary("Check for the Version of yelp");
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

  if ((res = isrpmvuln(pkg:"yelp", rpm:"yelp~2.28.1~17.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
