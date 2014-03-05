###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_snews_reorder_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# sNews 'reorder' Functions Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to insert arbitrary HTML and
  script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "sNews Version 1.7.1";
tag_insight = "The flaw is caused by improper validation of user-supplied input via
  'reorder' functions of administrator, which allows attackers to execute
  arbitrary HTML and script code on the web server.";
tag_solution = "No solution or patch is available as of 26th July, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://snewscms.com/home/download/";
tag_summary = "The host is running sNews and is prone to cross site scripting
  vulnerability.";

if(description)
{
  script_id(902544);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_cve_id("CVE-2011-2706");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("sNews 'reorder' Functions Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Jul/296");
  script_xref(name : "URL" , value : "http://security.bkis.com/snews-1-7-1-xss-vulnerability");

  script_description(desc);
  script_summary("Check for the version of sNews");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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
include("version_func.inc");
include("http_keepalive.inc");

## Get sNews Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

if(!can_host_php(port:phpPort)){
  exit(0);
}

foreach dir (make_list("/sNews", "/snews", "/", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir, "/readme.html"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## Confirm the application and Get version
  ver = eregmatch(pattern:'<title>sNews ([0-9.]+) ReadMe</title>', string:rcvRes);
  if(ver[1] != NULL)
  {
    ## Check for sNews version 1.7.1
    if(version_is_equal(version:ver[1], test_version:"1.7.1"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
