##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zikula_csrf_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Zikula CMS CSRF Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# - Updated By: Madhuri D <dmadhuri@secpod.com> on 2011-02-11
#      - Added CVE
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  commands in the context of affected site.
  Impact Level: Application.";
tag_affected = "Zikula version 1.2.4 and prior";

tag_insight = "The flaw exists because the application does not require multiple steps or
  explicit confirmation for sensitive transactions for majority of administrator
  functions such as adding new user, assigning user to administrative privilege.";
tag_solution = "Upgrade to the Zikula version 1.2.5
  For updates refer to http://zikula.org/";
tag_summary = "This host is running Zikula and is prone to cross-site request
  forgery vulnerability.";

if(description)
{
  script_id(801732);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_cve_id("CVE-2011-0535", "CVE-2011-0911");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Zikula CMS CSRF Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16097/");
  script_xref(name : "URL" , value : "http://securityreason.com/exploitalert/9921");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/98060/zikulacms-xsrf.txt");

  script_description(desc);
  script_summary("Check for the version of Zikula");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_zikula_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}
		

include("http_func.inc");
include("version_func.inc");

zkPort = get_http_port(default:80);
if(!get_port_state(zkPort)){
  exit(0);
}

## Get Zikula version from KB
if(!vers = get_version_from_kb(port:zkPort,app:"zikula")){
  exit(0);
}

if(version_is_less_equal(version:vers, test_version:"1.2.4")){
  security_hole(port:zkPort);
}
