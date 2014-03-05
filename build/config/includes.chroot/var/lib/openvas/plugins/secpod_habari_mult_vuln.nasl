##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_habari_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Habari Multiple Vulnerabilities
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
  site and determine the full path to the web root directory and other potentially
  sensitive information.
  Impact Level: Application.";
tag_affected = "Habari version 0.6.5";

tag_insight = "The flaws are due to
  - Input passed to the 'additem_form' parameter in 'system/admin/dash_additem.php'
    and 'status_data[]' parameter in 'system/admin/dash_status.php' is not
    properly sanitised before being returned to the user.
  - Error in '/system/admin/header.php' and '/system/admin/comments_items.php'
    script, which generate an error that will reveal the full path of the script.";
tag_solution = "Upgrade to Habari version 0.6.6 or later
  For updates refer to http://habariproject.org/en/download";
tag_summary = "This host is running Habari and is prone to multiple vulnerabilities.";

if(description)
{
  script_id(902326);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-31 07:04:16 +0100 (Fri, 31 Dec 2010)");
  script_cve_id("CVE-2010-4607", "CVE-2010-4608");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Habari Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42688");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15799/");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/xss_vulnerability_in_habari.html");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/xss_vulnerability_in_habari_1.html");

  script_description(desc);
  script_summary("Check Habari is vulnerable to XSS attack");
  script_category(ACT_ATTACK);
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
include("http_keepalive.inc");

## Get HTTP port
hbrPort = get_http_port(default:80);
if(!get_port_state(hbrPort)){
  exit(0);
}

foreach dir (make_list("/habari", "/", cgi_dirs()))
{
  ## Send and Receive Response
  sndReq = http_get(item:string(dir , "/"), port:hbrPort);
  rcvRes = http_send_recv(port:hbrPort, data:sndReq);

  ## Check application is Habari
  if("<title>My Habari</title>" >< rcvRes)
  {
    ## Try an exploit
    sndReq = http_get(item:string(dir, '/system/admin/dash_status.php?status_data' +
                          '[1]=<script>alert("OpenVAS-XSS-Testing");</script>'), port:hbrPort);
    rcvRes = http_send_recv(port:hbrPort, data:sndReq);

    ## Check the Response to confirm vulnerability
    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:rcvRes) &&
                    '<script>alert("OpenVAS-XSS-Testing");</script>' >< rcvRes){
      security_warning(hbrPort);
    }
  }
}
