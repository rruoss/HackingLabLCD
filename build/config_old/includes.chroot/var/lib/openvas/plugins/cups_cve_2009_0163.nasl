###############################################################################
# OpenVAS Vulnerability Test
# $Id: cups_cve_2009_0163.nasl 15 2013-10-27 12:49:54Z jan $
#
# CUPS '_cupsImageReadTIFF()' Integer Overflow Vulnerability
#
# Authors:      
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This host is running CUPS (Common UNIX Printing System) Service,
  which is prone to an Integer Overflow Vulnerabilities.

  Successful exploits may allow attackers to execute arbitrary code
  with the privileges of a user running the utilities. Failed exploit
  attempts likely cause denial-of-service conditions.";

tag_affected = "CUPS versions prior to 1.3.10";
tag_solution = "Updates are available. Please see http://www.cups.org/software.php
  for more information.";

if(description)
{
  script_id(100150);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-17 18:35:24 +0200 (Fri, 17 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-0163");
  script_bugtraq_id(34571);
  script_name("CUPS '_cupsImageReadTIFF()' Integer Overflow Vulnerability");
  desc = "

  Summary:
  " + tag_summary + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34571");
  script_xref(name : "URL" , value : "http://www.cups.org/str.php?L3031");

  script_description(desc);
  script_summary("Check for the version of CUPS service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 631);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

cupsPort = get_http_port(default:631);
if(!cupsPort){
  exit(0);
}

sndReq = http_get(item:string(dir, "/"), port:cupsPort);
recRes = http_send_recv(port:cupsPort, data:sndReq);
if(recRes == NULL){
  exit(0);
}

if("<TITLE>Home - CUPS" >< recRes &&
      egrep(pattern:"^HTTP/.* 200 OK", string:recRes))
{
  version = eregmatch(pattern: "<TITLE>Home - CUPS ([0-9.]+)</TITLE>", string: recRes);
  if(isnull(version[1]))exit(0);

  if(version_is_less(version:version[1], test_version:"1.3.10")) {
    security_hole(cupsPort);
    exit(0);
  }
}

exit(0);
