###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpalbum_multiple_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# phpAlbum.net Multiple Vulnerabilities
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
tag_impact = "Successful exploitation could result in a compromise of the application,
  theft of cookie-based authentication credentials, disclosure or modification
  of sensitive data.
  Impact Level: Application";
tag_affected = "phpAlbum.net version 0.4.1-14_fix06 and prior.";
tag_insight = "The flaws are due to
  - Failure in the 'main.php' script to properly verify the source of HTTP
    request.
  - Failure in the 'phpdatabase.php' script to properly sanitize user-supplied
    input in 'var3' variable.
  - Failure in the 'setup.php' script to properly sanitize user-supplied input
    in 'ar3', 'p_new_group_name' variables.";
tag_solution = "No solution or patch is available as of 15th April, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.phpalbum.net/dw";
tag_summary = "This host is running phpAlbum.net and is prone to Multiple
  vulnerabilities.";

if(description)
{
  script_id(801924);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("phpAlbum.net Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://videowarning.com/?p=6499");
  script_xref(name : "URL" , value : "http://www.phpdatabase.net/project/issues/402");
  script_xref(name : "URL" , value : "http://securityreason.com/wlb_show/WLB-2011040083");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/100428/phpalbumdotnet-xssxsrfexec.txt");

  script_description(desc);
  script_summary("Check if phpAlbum.net is vulnerable to XSS");
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

## Get phpAlbum.net Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## check host supports  php
if(!can_host_php(port:port)){
  exit(0);
}

## check for each possible path
foreach dir (make_list("/phpAlbum", "/phpAlbumnet", "/", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/main.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if('<title>phpAlbum.net</title>' >< res)
  {
     req = http_get(item:string(dir, '/main.php?cmd=setup&var1=user&var3=1">' +
                                '<script>alert("XSS-TEST")</script>'), port:port);
     res = http_keepalive_send_recv(port:port, data:req);
     ## Confirm exploit worked by checking the response
     if('><script>alert("XSS-TEST")</script>' >< res)
     {
       security_hole(port);
       exit(0);
     }
  }
}
