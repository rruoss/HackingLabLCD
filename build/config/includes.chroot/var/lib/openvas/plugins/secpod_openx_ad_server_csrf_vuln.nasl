###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openx_ad_server_csrf_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# OpenX Ad Server Cross Site Request Forgery Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to gain administrative
  privileges on the target application and can cause CSRF attack.
  Impact Level: Application";
tag_affected = "OpenX Ad Server version 2.8.7 and prior.";
tag_insight = "The flaw is due to an error in administrative interface, which can be
  exploited by remote attackers to force a logged-in administrator to perform
  malicious actions.";
tag_solution = "No solution or patch is available as of 25th July, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.openx.org/";
tag_summary = "The host is running OpenX Ad Server and is prone to cross site
  request forgery vulnerability.";

if(description)
{
  script_id(902458);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("OpenX Ad Server Cross Site Request Forgery Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103352/openxad-xsrf.txt");

  script_description(desc);
  script_summary("Check the version of OpenX Ad Server");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir(make_list("/openx", "/www", "/www/admin", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item: string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if(">Welcome to OpenX</" >< res)
  {
    openxVer = eregmatch(pattern:"OpenX v([0-9.]+)", string:res);
    if(openxVer[1] != NULL)
    {
      if(version_is_less_equal(version:openxVer[1], test_version:"2.8.7"))
      {
        security_warning(port);
        exit(0);
      }
    }
  }
}
