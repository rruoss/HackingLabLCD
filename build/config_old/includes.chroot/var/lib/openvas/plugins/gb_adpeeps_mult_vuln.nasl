###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adpeeps_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# AdPeeps 'index.php' Multiple Vulnerabilities.
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to insert arbitrary HTML and
  script code, which will be executed in a user's browser session in the context
  of an affected site when malicious data is viewed.
  Impact Level: Application";
tag_affected = "Adpeeps version 8.6.5d1 and prior.";
tag_insight = "The flaws are due to
  - Improper validation of user supplied data to the 'index.php' page via
    various parameters.
  - 'view_adrates' action with an invalid uid parameter, in 'index.php' reveals
    the installation path in an error message.
  - Application having a default password of 'admin' for the 'admin' account,
    which makes it easier for remote attackers to obtain access via requests
    to 'index.php'.";
tag_solution = "No solution or patch is available as of 27th July, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://adpeeps.com/signup.html";
tag_summary = "This host is running AdPeeps and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801414);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2009-4939", "CVE-2009-4943", "CVE-2009-4945");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("AdPeeps 'index.php' Multiple Vulnerabilities.");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35262");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50824");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50822");
  script_xref(name : "URL" , value : "http://forum.intern0t.net/intern0t-advisories/1049-adpeeps-8-5d1-cross-site-scripting-html-injection-vulnerabilities.html");

  script_description(desc);
  script_summary("Check AdPeeps is vulnerable by using exploit");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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

adPort = get_http_port(default:80);
if(!get_port_state(adPort)){
  exit(0);
}

foreach path (make_list("/", "/adpeeps", cgi_dirs()))
{
  ## Send and recieve the response
  sndReq = http_get(item:string(path, "/index.php"), port:adPort);
  rcvRes = http_send_recv(port:adPort, data:sndReq);

  ## Confirm application is Ad peeps
  if(">Ad Peeps" >< rcvRes ||
     ">Advertisement Management Control Panel<" >< rcvRes)
  {
    ## Try Exploit on Ad peeps
    sndReq = http_get(item:string(path,
                     "/index.php?loc=view_adrates&uid=1000000"), port:adPort);
    rcvRes = http_send_recv(port:adPort, data:sndReq);

    ## Check the response to confirm vulnerability
    if("mysql_result()" >< rcvRes &&
       "Unable to jump to row 0 on MySQL result" >< rcvRes)
    {
      security_hole(adPort);
      exit(0);
    }
  }
}
