##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bluesoft_sn_cms_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# BlueSoft Social Networking CMS SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.
  Impact Level: Application.";
tag_affected = "BlueSoft Social Networking CMS.";
tag_insight = "The flaw is due to input passed via the 'photo_id' parameter to
  'user_profile.php', which is not properly sanitised before being used in
  a SQL query.";
tag_solution = "No solution or patch is available as of 18th July 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.shopbluesoft.com/";
tag_summary = "This host is running BlueSoft Social Networking CMS and is prone to
  SQL injection vulnerability.";

if(description)
{
  script_id(801957);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-19 14:57:20 +0200 (Tue, 19 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("BlueSoft Social Networking CMS SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103119/socialnetworking-sql.txt");


  script_description(desc);
  script_summary("Check if BlueSoft Social Networking CMS is vulnerable for SQL Injection attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
include("http_keepalive.inc");

## Get the port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("/cms", "/cncms", cgi_dirs()))
{
  ## Construct the request
  file = dir + "/index.php";
  sndReq = string("GET ", file, " HTTP/1.1", "\r\n",
                  "Host: ", get_host_name(), "\r\n\r\n");
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if("Powered By" >< rcvRes && "The Social Networking CMS" >< rcvRes &&
     ">ShopBlueSoft.com<" >< rcvRes)
  {
    ## Construct the exploit request
    exploit = string(dir, "/user_profile.php?view=photo&photo_id='");
    sndReq = string("GET ", exploit, " HTTP/1.1", "\r\n",
                    "Host: ", get_host_name(), "\r\n\r\n");

    rcvRes = http_send_recv(port:port, data:sndReq);

    ## Check the source code of the function in response
    if("error in your SQL syntax;">< rcvRes)
    {
      security_hole(port);
      exit(0);
    }
  }
}
