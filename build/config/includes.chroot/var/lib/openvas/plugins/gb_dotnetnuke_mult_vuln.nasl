###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotnetnuke_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# DotNetNuke Multiple Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to gain unauthorized access to
  the server.
  Impact Level: Application";
tag_affected = "DotNetNuke version prior to 5.x.";
tag_insight = "Multiple flaws are present in DotNetNuke. The application fails to
  revalidate file and folder permissions correctly for uploads. This allows
  remote file upload and unauthorized access to the server, files and database.";
tag_solution = "No solution or patch is available as of 07th July 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.dotnetnuke.com/";
tag_summary = "The host is running DotNetNuke and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802306);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("DotNetNuke Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/16462");

  script_description(desc);
  script_summary("Determine if DotNetNuke is prone to auth bypass");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

## Send and Recieve the response
req = string("GET /DesktopModules/AuthenticationServices/OpenID/license.txt HTTP/1.1\r\n",
             "Host: ", get_host_ip(), "\r\n\r\n");
res = http_keepalive_send_recv(port:port,data:req);

if("DotNetNuke" >< res)
{
  foreach path (make_list("FeedbackDesigner", "FlashSlide", "TellMyFriends",
                          "Complete%20Feedback%20Designer", "FlashBoard"))
  {
    ## Send and Recieve the response
    filename = string("/DesktopModules/", path , "/ajaxfbs/browser.html");

    req = string("GET ", filename ," HTTP/1.1\r\n",
                 "Host: ", get_host_ip(), "\r\n\r\n");
    res = http_keepalive_send_recv(port:port,data:req);

    if("200 OK" >< res && "create the folder">< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}
