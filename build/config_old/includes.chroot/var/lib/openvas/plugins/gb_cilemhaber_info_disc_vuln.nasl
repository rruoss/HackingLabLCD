###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cilemhaber_info_disc_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Cilem Haber Information Disclosure Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to download the database
  and obtain sensitive information.
  Impact Level: Application";
tag_affected = "Cilem Haber Version 1.4.4";
tag_insight = "The flaw is caused by improper restrictions on the 'cilemhaber.mdb' database
  file. By sending a direct request, a remote attacker could download the
  database and obtain sensitive information.";
tag_solution = "No solution or patch is available as of 08th October, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.cilemhaber.com/default.asp";
tag_summary = "The host is running Cilem Haber and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_id(801605);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Cilem Haber Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62249");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15199/");

  script_description(desc);
  script_summary("Check if Cilem Haber is vulnerable to Information Disclosure");
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

foreach dir (make_list("/cilemhaber", "/", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/www/default.asp"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if("cilemhaber" >< res)
  {
    ## Try an exploit
    req = http_get(item:string(dir,"/db/cilemhaber.mdb"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
 
    ## Check the Response to confirm vulnerability
    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) && 
                    'Standard Jet DB' >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
