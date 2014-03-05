###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multi_lingual_ecommerce_system_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Multi-lingual E-Commerce System Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_impact = "Successful exploitation will allow attacker to obtain potentially
  sensitive information and to execute arbitrary PHP code in the context
  of the webserver process.
  Impact Level: Application/System";
tag_affected = "Multi-lingual E-Commerce System Version 0.2";
tag_insight = "- Local file inclusion vulnerability due to improper validation of user
    supplied input to the 'lang' parameter in index.php.
  - Information Disclosure vulnerability due to reserved informations in
    database.inc.
  - Arbitrary File Upload vulnerability due to improper validation of files
    uploaded via product_image.php.";
tag_solution = "No solution or patch is available as of 13th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/mlecsphp/";
tag_summary = "This host is running Multi-lingual E-Commerce System and is prone
  to multiple Vulnerabilities.";

if(description)
{
  script_id(801285);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Multi-lingual E-Commerce System Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/8480/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/502798");

  script_description(desc);
  script_summary("Check if Multi-lingual E-Commerce System is vulnerable");
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

foreach dir (make_list("/shop", "/genericshop", "/", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if( ('<title>Multi-lingual Shop</title>' >< res) )
  {
    foreach file (make_list("etc/passwd","boot.ini"))
    {
      ## Try attack and check the response to confirm vulnerability.
      if(http_vuln_check(port:port, url:string (dir,"/index.php?lang=../../" +
                         "../../../../../../../../",file,"%00"),
                         pattern:"(root:.*:0:[01]:|\[boot loader\])"))
      {
        security_hole(port:port);
        exit(0);
      }
    }
  }
}
