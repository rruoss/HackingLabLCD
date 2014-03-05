###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_jaxcms_lfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# JaxCMS 'index.php' Local File Inclusion Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
# You should have receivedreceived a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation could allow the attackers to include and execute
  local files via directory traversal sequences and URL-encoded NULL bytes.
  Impact Level: Application";
tag_affected = "JaxCMS version 1.0 and prior";
tag_insight = "The flaw is due to error in 'index.php' which is not properly sanitizing user
  input passed to the 'p' parameter.";
tag_solution = "No solution or patch is available as of 31st March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.pixiescripts.com/";
tag_summary = "The host is running JaxCMS and is prone to local file inclusion
  vulnerability.";

if(description)
{
  script_id(900756);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-01 11:04:35 +0200 (Thu, 01 Apr 2010)");
  script_cve_id("CVE-2010-1043");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("JaxCMS 'index.php' Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/62161");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38524");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11359");

  script_description(desc);
  script_copyright("Copyright (c) 2010 SecPod");
  script_summary("Check through the attack string on JaxCMS");
  script_category(ACT_ATTACK);
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

jaxPort = get_http_port(default:80);
if(!jaxPort){
  exit(0);
}

foreach dir (make_list("/JaxCMS", "/jaxcms", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:jaxPort);
  rcvRes = http_send_recv(port:jaxPort, data:sndReq);
  if("JaxCMS" >< rcvRes)
  {
    ##  Platform independent Attack string
    sndReq = http_get(item:string(dir, "/index.php?p=OpenVAS_LFI%00"), port:jaxPort);
    rcvRes = http_send_recv(port:jaxPort, data:sndReq);
    if("failed to open stream" >< rcvRes)
    {
      security_hole(jaxPort);
      exit(0);
    }
  }
}
