###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_abantecart_mult_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# AbanteCart Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";

tag_affected = "AbanteCart version 1.1.3 and prior";
tag_insight = "Input passed via the 'limit', 'page', 'rt', 'sort', 'currency', 'product_id',
  'language', 's', 'manufacturer_id', and 'token' GET parameters to index.php
  is not properly sanitized before being returned to the user.";
tag_solution = "No solution or patch is available as of 26th February, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.abantecart.com";
tag_summary = "This host is installed with AbanteCart and is prone to multiple
  cross site scripting vulnerabilities.";

if(description)
{
  script_id(902952);
  script_version("$Revision: 11 $");
  script_bugtraq_id(57948);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-26 11:48:51 +0530 (Tue, 26 Feb 2013)");
  script_name("AbanteCart Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/90225");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52165");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/82073");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013020095");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120273");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/52165");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5125.php");

  script_description(desc);
  script_summary("Check if AbanteCart is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 SecPod");
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
include("http_keepalive.inc");

port = "";
dir = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
 port = 80;
}

## Check the port status
if(!get_port_state(port)){
 exit(0);
}

## Check the php support
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over the possible paths
foreach dir (make_list("", "/abantecart", "/cart", cgi_dirs()))
{
  ## Application Confirmation
  if(http_vuln_check(port:port, url:dir + "/index.php",
     pattern:">AbanteCart<", check_header:TRUE,
     extra_check:make_list('>Powered by Abantecart', '>Cart<')))
  {
    ## Construct attack request
    url = dir + '/index.php?limit="><script>alert(document.cookie);</script>';

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"><script>alert\(document.cookie\);</script>",
       extra_check:">AbanteCart<"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
