###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_guest_acc_dos_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# CUPS Subscription Incorrectly uses Guest Account DoS Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation causes Denial of Service condition.
  Impact Level: Application";
tag_affected = "CUPS Versions prior to 1.3.8 on Linux.";
tag_insight = "The flaw is due to error in web interface (cgi-bin/admin.c), which
  uses the guest username when a user is not logged on to the web server.
  This leads to CSRF attacks with the add/cancel RSS subscription functions.";
tag_solution = "Upgrade to CUPS Version 1.3.8 or later.
  http://www.cups.org/software.php";
tag_summary = "This host is running CUPS (Common UNIX Printing System) Service,
  which is prone to Denial of Service Vulnerability.";

if(description)
{
  script_id(800142);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-26 16:25:46 +0100 (Wed, 26 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-5183", "CVE-2008-5184");
  script_bugtraq_id(32419);
  script_name("CUPS Subscription Incorrectly uses Guest Account DoS Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.cups.org/str.php?L2774");
  script_xref(name : "URL" , value : "http://www.gnucitizen.org/blog/pwning-ubuntu-via-cups/");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2008/11/19/3");

  script_description(desc);
  script_summary("Check for the Version of CUPS service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 631);
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

cupsPort = get_http_port(default:631);
if(!cupsPort){
  cupsPort = 631;
}

sndReq = http_get(item:string(dir, "/"), port:cupsPort);
recRes = http_send_recv(port:cupsPort, data:sndReq);
if(recRes == NULL){
  exit(0);
}

if("<TITLE>Home - CUPS" >< recRes)
{
  cupsVer = eregmatch(pattern:"CUPS ([0-9.]+)", string:recRes);
  if(cupsVer[1] != NULL)
  {
    # Check for CUPS Version < 1.3.8
    if(version_is_less(version:cupsVer[1], test_version:"1.3.8")){
      security_hole(port);
    }
  }
}
