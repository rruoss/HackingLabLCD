###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolphin_multiple_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Dolphin Multiple Reflected Cross Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary script code
  in the browser of an unsuspecting user in the context of an affected site.
  Impact Level: Application";
tag_affected = "Dolphin version 7.0.4 Beta";
tag_insight = "Multiple flaws are due to:
  - Input passed via the 'explain' parameter in 'explanation.php' script
    and 'relocate' parameter in '/modules/boonex/custom_rss/post_mod_crss.php'
    script is not properly sanitized before being returned to the user.";
tag_solution = "No solution or patch is available as of 01st April, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.boonex.com/dolphin/";
tag_summary = "This host is running Dolphin and is prone to multiple reflected cross-site
  scripting vulnerabilities.";

if(description)
{
  script_id(801910);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Dolphin Multiple Reflected Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/98408/Dolphin7.0.4-xss.txt");

  script_description(desc);
  script_summary("Check for Dolphin Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
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

dolPort = get_kb_item("Services/www");
if(!dolPort){
  exit(0);
}

foreach path (make_list("/dolphin", "/", cgi_dirs()))
{
  ## Check for the passible paths
  sndReq = http_get(item:string(path, "/index.php"), port:dolPort);
  rcvRes = http_keepalive_send_recv(port:dolPort, data:sndReq);

  ##  Confirm server installation for each path
  if("<title>Dolphin" >< rcvRes)
  {
    ## Send the constructed request
    sndReq = http_get(item:string(path, '/modules/boonex/custom_rss/' +
                      'post_mod_crss.php?relocate="><script>alert' +
                      '(document.cookie)</script>'), port:dolPort);
    rcvRes = http_keepalive_send_recv(port:dolPort, data:sndReq);

    ## Check the response after exploit
    if("><script>alert(document.cookie)</script>" >< rcvRes)
    {
      security_warning(port:dolPort);
      exit(0);
    }
  }
}
