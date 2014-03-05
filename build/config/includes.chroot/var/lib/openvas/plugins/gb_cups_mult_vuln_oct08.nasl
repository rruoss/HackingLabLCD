###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_mult_vuln_oct08.nasl 16 2013-10-27 13:09:52Z jan $
#
# CUPS Multiple Vulnerabilities - Oct08
#
# Authors:      Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code or
  compromise a vulnerable system.
  Impact Level: System";
tag_affected = "CUPS versions prior to 1.3.9";
tag_insight = "The flaws are due to
  - an error in the implementation of the HP-GL/2 filter and can be
    exploited to cause buffer overflows with HP-GL/2 files containing overly
    large pen numbers.
  - an error within the read_rle8() and read_rle16() functions when
    parsing malformed Run Length Encoded(RLE) data within Silicon Graphics
    Image(SGI) files and can exploited to cause heap-based buffer overflow
    with a specially crafted SGI file.
  - an error within the WriteProlog() function included in the texttops
    utility and can be exploited to cause a heap-based buffer overflow with
    specially crafted file.";
tag_solution = "Upgrade to CUPS version 1.3.9
  http://www.cups.org/software.php";
tag_summary = "This host is running CUPS (Common UNIX Printing System) Service,
  which is prone to Buffer Overflow and Integer Overflow Vulnerabilities.";

if(description)
{
  script_id(800111);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-14 16:26:50 +0200 (Tue, 14 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-3639", "CVE-2008-3640", "CVE-2008-3641");
  script_bugtraq_id(31681, 31688, 31690);
  script_name("CUPS Multiple Vulnerabilities - Oct08");
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
  script_xref(name : "URL" , value : "http://cups.org/articles.php?L575");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32226/");
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2782/");

  script_description(desc);
  script_summary("Check for the version of CUPS service");
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
  if(egrep(pattern:"CUPS (1\.[0-2](\..*)?|1\.3(\.[0-8])?($|[^.0-9]))",
           string:recRes)){
    security_hole(cupsPort);
  }
}
