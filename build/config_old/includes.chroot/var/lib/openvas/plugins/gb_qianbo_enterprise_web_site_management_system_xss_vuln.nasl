###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qianbo_enterprise_web_site_management_system_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Qianbo Enterprise Web Site Management System Cross Site Scripting Vulnerability
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
  theft of cookie-based authentication credentials.
  Impact Level: Application";
tag_affected = "Qianbo Enterprise Web Site Management System";
tag_insight = "The flaw is due to failure in the 'en/Search.Asp?' script to properly
  sanitize user-supplied input in 'Range=Product&Keyword' variable.";
tag_solution = "No solution or patch is available as of 15th April, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.qianbo.com.cn/";
tag_summary = "This host is running Qianbo Enterprise Web Site Management System
  and is prone to cross site scripting vulnerability.";

if(description)
{
  script_id(801925);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Qianbo Enterprise Web Site Management System Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://sec.jetlib.com/tag/qianbo");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/100425/qianbo-xss.txt");
  script_xref(name : "URL" , value : "http://www.rxtx.nl/qianbo-enterprise-web-site-management-system-cross-site-scripting-2/");

  script_description(desc);
  script_summary("Check if Qianbo Enterprise Web Site Management System is vulnerable to XSS");
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
if(!can_host_asp(port:port)){
  exit(0);
}

## check for each possible path
foreach dir (make_list("/qianbo", "/enqianbo", "/", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/en/index.asp"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if('QianboEmail' >< res && 'QianboSubscribe' >< res)
  {
     req = http_get(item:string(dir, 'en/Search.Asp?Range=Product&Keyword' +
                         '=<script>alert("XSS-TEST")</script>'), port:port);
     res = http_keepalive_send_recv(port:port, data:req);

     ## Confirm exploit worked by checking the response
     if('><script>alert("XSS-TEST")</script>' >< res)
     {
       security_warning(port);
       exit(0);
     }
  }
}
