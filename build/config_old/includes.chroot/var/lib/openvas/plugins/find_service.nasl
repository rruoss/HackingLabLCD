###############################################################################
# OpenVAS Vulnerability Test
# $Id: find_service.nasl 69 2013-11-20 15:01:22Z mime $
#
# Wrapper for calling built-in NVT "find_service" which was previously
# a binary ".nes".
#
# Authors:
# Jan-Oliver Wagner <Jan-Oliver.Wagner@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This plugin attempts to guess which
service is running on the remote ports. For instance,
it searches for a web server which could listen on
another port than 80 and set the results in the plugins
knowledge base.";

if (description)
{
 script_id(10330);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 69 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-20 16:01:22 +0100 (Wed, 20 Nov 2013) $");
 script_tag(name:"creation_date", value:"2011-01-14 10:12:23 +0100 (Fri, 14 Jan 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Services");

desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 script_summary("Find what is listening on which port");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("Written by Renaud Deraison <deraison@cvs.nessus.org>");

 script_add_preference(name: "Number of connections done in parallel : ",
   value: "6", type: "entry");
 script_add_preference(name: "Network connection timeout : ",
   value: "5", type: "entry");
 script_add_preference(name: "Network read/write timeout : ",
   value: "5", type: "entry");
 script_add_preference(name: "Wrapped service read timeout : ",
   value: "2", type: "entry");
 script_add_preference(name:"SSL certificate : ", type:"file", value:"");
 script_add_preference(name:"SSL private key : ", type:"file", value:"");
 script_add_preference(name:"PEM password : ", type:"password", value:"");
 script_add_preference(name:"CA file : ", type:"file", value:"");

 script_add_preference(name:"Test SSL based services", type:"radio", value:"All;None");

 script_timeout(4*360);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

plugin_run_find_service();

