###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_power_manager_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# HP Power Manager Login Form Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow users to cause a Denial of Service condition.
  Impact Level: Application";
tag_affected = "HP Power Manager (HPPM) before 4.3.2";
tag_insight = "The flaw is due to a boundary error when processing URL parameters
  passed to the login form of the management web server. It can be exploited
  to cause a stack-based buffer overflow via a specially crafted 'Login' variable.";
tag_solution = "Upgrade to HP Power Manager (HPPM) 4.3.2 or later,
  For updates refer to
  http://h18000.www1.hp.com/products/servers/proliantstorage/power-protection/software/power-manager/index.html";
tag_summary = "The host is running HP Power Manager and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(801569);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-18 07:48:41 +0100 (Tue, 18 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2010-4113");
  script_name("HP Power Manager Login Form Buffer Overflow Vulnerability");
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


  script_description(desc);
  script_summary("Check for the version of HP Power Manager");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("hp_power_manager_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42644");
  script_xref(name : "URL" , value : "http://marc.info/?l=bugtraq&amp;m=129251322532373&amp;w=2");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-292/");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Dec/1024902.html");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

if(!vers = get_kb_item(string("www/", port, "/hp_power_manager"))){
  exit(0);
}

if(!isnull(vers) && vers >!< "unknown")
{
  if(version_is_less(version: vers, test_version: "4.3.2")){
      security_hole(port:port);
  }
}
