# OpenVAS Vulnerability Test
# $Id: squid_2612.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Squid < 2.6.STABLE12
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# Updated: 04/07/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2007 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "A vulnerability in TRACE request processing has been reported in Squid,
  which can be exploited by malicious people to cause a denial of service.";

tag_solution = "Upgrade to squid 2.6 or newer.";

if(description)
{
  script_id(80017);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(80017);
  script_cve_id("CVE-2007-1560");
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;  script_description(desc);
  script_name("Squid < 2.6.STABLE12");
  script_summary("Determines squid version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2007 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.squid-cache.org/Advisories/SQUID-2007_1.txt");
  exit(0);
}


include("version_func.inc");
port = get_kb_item("Services/http_proxy");
if(!port){
  port = 3128;
}

if(!get_port_state(port)){
  port = 8080;
}


squidVer =get_kb_item(string("www/", port, "/Squid"));
if(!squidVer){
  exit(0);
}
# checking for the Version < =2.6
if(egrep(pattern:"2\.([0-5]\.|6\.STABLE([0-9][^0-9]|1[01][^0-9]))", string:squidVer))
{
  security_warning(port);
  exit(0);
}
