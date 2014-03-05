##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hesk_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# HESK Multiple Cross-site Scripting (XSS) Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in context of affected website.
  Impact Level: Application";
tag_affected = "HESK version 2.2 and prior.";

tag_insight = "The flaws are due to improper validation of
  - input passed via the 'hesk_settings[tmp_title]' and 'hesklang[ENCODING]'
    parameters to '/inc/header.inc.php'.
  - input passed via 'hesklang[attempt]' parameter to various files in '/inc/'
    directory.
  - input appended to the URL after '/language/en/text.php', before being
  returned to the user.";
tag_solution = "Upgrade to HESK version 2.3 or later.
  For updates refer to http://www.hesk.com/";
tag_summary = "This host is running HESK and is prone to multiple cross-site
  scripting vulnerabilities.";

if(description)
{
  script_id(802132);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("HESK Multiple Cross-site Scripting (XSS) Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519148");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/multiple_xss_in_hesk.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103733/hesk-xss.txt");

  script_description(desc);
  script_summary("Check if HESK is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
hsPort = get_http_port(default:80);
if(!get_port_state(hsPort)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:hsPort)){
  exit(0);
}

foreach dir (make_list("/hesk", "/Hesk", "", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:hsPort);
  rcvRes = http_keepalive_send_recv(port:hsPort, data:sndReq);

  ## Confirm the application
  if('>Powered by <' >< rcvRes && '> HESK&' >< rcvRes)
  {
    url = string(dir, '/inc/header.inc.php?hesklang[ENCODING]="><script>' +
                      "alert('OpenVAS-XSS');</script>");

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:hsPort, url:url, pattern:"><script>alert" +
                          "\('OpenVAS-XSS'\);</script>"))
    {
      security_warning(hsPort);
      exit(0);
    }
  }
}
