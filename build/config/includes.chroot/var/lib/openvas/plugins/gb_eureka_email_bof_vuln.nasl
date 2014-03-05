###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eureka_email_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Eureka Email Stack-Based Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows remote attackers to crash an affected client
  or execute arbitrary code by tricking a user into connecting to a malicious
  POP3 server.

  Impact level: Application.";

tag_affected = "Eureka Email version 2.2q and prior.";
tag_insight = "The flaw is due to a boundary error in the processing POP3 responses.
  This can be exploited to cause a stack-based buffer overflow via an overly long
  error response.";
tag_solution = "No solution or patch is available as of 05th November, 2009. Information
  regarding this issue will update once the solution details are available.
  For updates refer to http://www.eureka-email.com/";
tag_summary = "This host is installed with Eureka Email and is prone to stack-based
  buffer overflow vulnerability.";

if(description)
{
  script_id(801041);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3837");
  script_name("Eureka Email Stack-Based Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53940");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/product/27632/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3025");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.org/0910-exploits/eurekamc-dos.txt");

  script_description(desc);
  script_summary("Check for the version of Eureka Email");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_eureka_email_detect.nasl");
  script_require_keys("EurekaEmail/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

eeVer = get_kb_item("EurekaEmail/Ver");
if(eeVer != NULL)
{
  # Eureka Email 2.2q (2.2.0.1)
  if(version_is_less_equal(version:eeVer, test_version:"2.2.0.1")){
    security_hole(0);
  }
}
