##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_lm_starmail_paidmail_sql_inj_n_rfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# LM Starmail SQL Injection and Remote File Inclusion Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to view, add, modify or
  delete information in the back-end database.
  Impact Level: Application.";
tag_affected = "LM Starmail Paidmail version 2.0";

tag_insight = "The flaw caused by improper validation of user-supplied input via the 'ID'
  parameter to 'paidbanner.php' and 'page' parameter to 'home.php'.";
tag_solution = "No solution or patch is available as of 23rd February 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.script-shop24.de";
tag_summary = "This host is running LM Starmail Paidmail and is prone SQL Injection
  and Remote File Inclusion Vulnerabilities.";

if(description)
{
  script_id(902099);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-30 16:09:21 +0200 (Mon, 30 Aug 2010)");
  script_cve_id("CVE-2009-4993", "CVE-2009-4992");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("LM Starmail Paidmail SQL Injection and Remote File Inclusion Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://inj3ct0r.com/exploits/5624");

  script_description(desc);
  script_summary("Check LM Starmail Paidmail vulnerable to SQL Injection and RFI attacks");
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

## Get HTTP Port
lmPort = get_http_port(default:80);
if(!get_port_state(lmPort)){
  exit(0);
}

foreach dir (make_list("/lm_starmail_paidmail", "/", cgi_dirs()))
{
  ## Send and Recieve request
  sndReq = http_get(item:string(dir, "/index.php"), port:lmPort);
  rcvRes = http_send_recv(port:lmPort, data:sndReq);

  ## Confirm application is LM Starmail Paidmail
  if("<title> LM Starmail" >< rcvRes)
  {
     ## Try exploit and check response to confirm vulnerability
    sndReq = http_get(item:string(dir, "/paidbanner.php?ID=-1+union+select+1,2,3" +
                        ",4,5,user(),7,8,9,10--"), port:lmPort);
    rcvRes = http_send_recv(port:lmPort, data:sndReq);
    if("mysql_fetch_array(): supplied argument is not a valid MySQL result resource" >< rcvRes){
      security_hole(lmPort);
    }
  }
}
