##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cachelogic_expired_domains_script_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Cachelogic Expired Domains Script Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code and manipulate SQL queries by injecting arbitrary SQL code
  in a user's browser session in context of an affected site.
  Impact Level: Application.";
tag_affected = "Cachelogic Expired Domains Script version 1.0";

tag_insight = "Multiple flaws are due to,
  - An error in 'stats.php' when handling the 'name' and 'ext' parameters.
  - A full path disclosure vulnerability in 'index.php' when handling various
    parameters.
  - A SQL injection vulnerability in 'index.php' when handling 'ncharacter'
    parameter.";
tag_solution = "Apply the patch from below link,
  http://code.google.com/p/eventh/downloads/list";
tag_summary = "This host is running cahelogic expired domains script and is prone
  multiple vulnerabilities.";

if(description)
{
  script_id(902449);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Cachelogic Expired Domains Script Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17428/");
  script_xref(name : "URL" , value : "http://itsecuritysolutions.org/2011-03-24_Cachelogic_Expired_Domains_Script_1.0_multiple_security_vulnerabilities/");

  script_description(desc);
  script_summary("Check Cachelogic Expired Domains Script is vulnerable to XSS attacks");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
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
include("version_func.inc");

cedmPort = get_http_port(default:80);
if(!get_port_state(cedmPort)){
  exit(0);
}

foreach dir (make_list("/demo", "/cedm", cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/index.php"), port:cedmPort);
  rcvRes = http_send_recv(port:cedmPort, data:sndReq);

  ## Confirm application
  if(">Cachelogic Expired and Deleted Domain" >< rcvRes)
  {
    ## Try expliot and check response
    sndReq = http_get(item:string(dir, "/stats.php?ext='><script>alert" +
             "('XSS-TEST')</script><p+'"), port:cedmPort);
    rcvRes = http_send_recv(port:cedmPort, data:sndReq);

    ## Check the Response string
    if("><script>alert('XSS-TEST')</script>" >< rcvRes)
    {
      security_hole(cedmPort);
      exit(0);
    }
  }
}
