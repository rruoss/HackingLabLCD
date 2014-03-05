###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_beanstalkd_remote_cmd_exec_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Beanstalkd Job Data Remote Command Execution Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to execute Beanstalk
  client commands within the context of the affected application.
  Impact Level: Application";
tag_affected = "Beanstalkd version 1.4.5 and prior.";
tag_insight = "The flaw is caused by improper handling of put commands defining a job
  by the dispatch_cmd function. A remote attacker could exploit this
  vulnerability using a specially-crafted job payload data to execute
  arbitrary Beanstalk commands.";
tag_solution = "Upgrade to Beanstalkd version 1.4.6 or later,
  For updates refer to http://kr.github.com/beanstalkd/download.html";
tag_summary = "This host is running Beanstalkd and is prone to remote command
  execution vulnerability.";

if(description)
{
  script_id(901122);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-21 15:32:44 +0200 (Mon, 21 Jun 2010)");
  script_cve_id("CVE-2010-2060");
  script_bugtraq_id(40516);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Beanstalkd Job Data Remote Command Execution Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59107");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40032");
  script_xref(name : "URL" , value : "http://github.com/kr/beanstalkd/commit/2e8e8c6387ecdf5923dfc4d7718d18eba1b0873d");

  script_description(desc);
  script_summary("Check for the Beanstalkd version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_beanstalkd_detect.nasl");
  script_require_keys("Beanstalkd/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Get version from KB
ver = get_kb_item("Beanstalkd/Ver");
if(!ver){
  exit(0);
}

## Check for Beanstalkd version prior to 1.4.6
if(version_is_less(version:ver, test_version:"1.4.6")){
  security_hole(0);
}
