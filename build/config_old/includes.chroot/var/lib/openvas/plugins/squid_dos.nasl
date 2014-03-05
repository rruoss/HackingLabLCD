# OpenVAS Vulnerability Test
# $Id: squid_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: DoSable squid proxy server
#
# Authors:
# Adam Baldwin <adamb@amerion.net>
# Updated: 04/07/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2001 Adam Baldwin
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
tag_summary = "A problem exists in the way the remote Squid proxy server handles a
  special 'mkdir-only' PUT request, and causes denial of service to the proxy
  server.
  An attacker may use this flaw to prevent your LAN users from accessing
  the web.";

tag_solution = "Apply the vendor released patch, for squid it is located here:
  www.squid-cache.org.  You can also protect yourself by enabling access lists
  on your proxy.";

if(description)
{
  script_id(10768);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3354);
  script_cve_id("CVE-2001-0843");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
  script_name("DoSable squid proxy server");
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;  script_description(desc);
  script_summary("Determines via ver. if a proxy server is DoSable");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2001 Adam Baldwin");
  script_dependencies("secpod_squid_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
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

data =get_kb_item(string("www/", port, "/Squid"));
if(!data){
  exit(0);
}

# checking for the Version < =2.4
if(("2.3"  >< data) && (("STABLE1" >< data)||("STABLE3" >< data)||
    ("STABLE4" >< data)||("STABLE5" >< data)))
{
  security_warning(port);
  exit(0);      
}

#CHECK VERSION 2.4
if(("2.4" >< data) && (("STABLE1" >< data) ||("PRE-STABLE2" >< data) || 
   ("PRE-STABLE" >< data) ||("DEVEL4" >< data)||("DEVEL2" >< data)))
{
  security_warning(port);
  exit(0);                                                                                                              
}

