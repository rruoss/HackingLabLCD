##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagiosxi_multiple_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Nagios XI Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <snatu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to conduct spoofing,
  cross-site scripting and cross-site request forgery attacks.
  Impact Level: Application";

tag_affected = "Nagios XI versions 2012R1.5b and 2012R1.5";
tag_insight = "- Input passed via the 'xiwindow' GET parameter to admin/index.php is not
     properly verified before being used to be displayed as iframe.
   - Input passed via multiple GET parameters to various scripts is not properly
     sanitized before being returned to the user.
   - The application allows users to perform certain actions via HTTP requests
     without properly verifying the requests.
   - Input passed via the 'address' POST parameter to
     includes/components/autodiscovery/index.php (when 'mode' is set to 'newjob',
     'update' is set to '1', and 'job' is set to '-1') is not properly verified
     before being used. This can be exploited to inject and execute arbitrary
     shell commands.";
tag_solution = "No solution or patch is available as on 08th, February 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.nagios.com/products/nagiosxi";
tag_summary = "This host is running Nagios XI and is prone to multiple
  vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803168";
CPE = "cpe:/a:nagios:nagiosxi";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-07 18:25:24 +0530 (Thu, 07 Feb 2013)");
  script_name("Nagios XI Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/89847");
  script_xref(name : "URL" , value : "http://www.osvdb.org/89843");
  script_xref(name : "URL" , value : "http://www.osvdb.org/89844");
  script_xref(name : "URL" , value : "http://www.osvdb.org/89846");
  script_xref(name : "URL" , value : "http://www.osvdb.org/89842");
  script_xref(name : "URL" , value : "http://www.osvdb.org/89893");
  script_xref(name : "URL" , value : "http://www.osvdb.org/89894");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52011");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120038");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Feb/10");

  script_description(desc);
  script_summary("Check vulnerable version of Nagios XI");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_XI_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("nagiosxi/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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
include("version_func.inc");

port = "";
vers = "";

## Get the application port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  port = 80;
}

## check the port status
if(!get_port_state(port)){
  exit(0);
}

## check for the PHP support
if(!can_host_php(port:port)){
  exit(0);
}

## Get the application version
if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## check the vulnerable versions
if("unknown" >!< vers && (vers == "2012R1.5b" || vers == "2012R1.5"))
{
  security_hole(port);
  exit(0);
}
