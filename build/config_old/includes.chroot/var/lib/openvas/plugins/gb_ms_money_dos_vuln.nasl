###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_money_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Money 'prtstb06.dll' Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to change the vulnerable
  EIP value and can cause denial of service to the application.
  Impact Level: Application";
tag_affected = "Microsoft Money 2006 on Windows.";
tag_insight = "The flaw is due to an error in the Windows Based Script Host which lets
  the attacker execute arbitrary codes in the vulnerable buffer to crash
  the application.";
tag_solution = "No solution or patch is available as of 08th January, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/MONEY/default.mspx";
tag_summary = "This host has Microsoft Money installed and is prone to Denial
  of Service Vulnerability.";

if(description)
{
  script_id(800218);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-08 14:06:04 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5823");
  script_name("Microsoft Money 'prtstb06.dll' Denial of Service vulnerability");
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
  script_xref(name : "URL" , value : "http://jbrownsec.blogspot.com/2008/12/new-year-research-are-upon-us.html");

  script_description(desc);
  script_summary("Check for the Version of Microsoft Money");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ms_money_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


msmVer = get_kb_item("MS/Money/Version");
if(!msmVer){
  exit(0);
}

# Check for version Microsoft Money 2006
if(msmVer =~ "2006"){
  security_warning(0);
}
