###############################################################################
# OpenVAS Vulnerability Test
# $Id:secpod_ftp_anonymous.nasl 1006 2009-02-10 17:05:29Z Feb $
#
# Anonymous FTP Checking
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Modified 2009-03-24 by Michael Meyer
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_summary = "This FTP Server allows anonymous logins.

   A host that provides an FTP service may additionally provide Anonymous FTP
   access as well. Under this arrangement, users do not strictly need an account
   on the host. Instead the user typically enters 'anonymous' or 'ftp' when
   prompted for username. Although users are commonly asked to send their email
   address as their password, little to no verification is actually performed on
   the supplied data.";

tag_solution = "If you do not want to share files, you should disable anonymous logins.";

desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
if(description)
{
  script_id(900600);
  script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-03-12 10:50:11 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_cve_id("CVE-1999-0497");
  script_name("Anonymous FTP Checking");
  script_description(desc);
  script_summary("Check for remote ftp anonymous login");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("FTP");
  script_dependencies("find_service.nasl","ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("ftp_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

if(get_kb_item('ftp/'+port+'/broken'))exit(0);

if(!get_port_state(ftpPort)){
  exit(0);
}

soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

domain = get_kb_item("Settings/third_party_domain");
if(isnull(domain)) {
 domain = this_host_name();;
}

user = "anonymous";
passwd = string("openvas@", domain);

login_details = ftp_log_in(socket:soc1, user:user, pass:passwd);
if(login_details)
{
  ftpPort2 = ftp_get_pasv_port(socket:soc1);
  if(ftpPort2)
  {
    soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
    if(soc2)
    {
      send(socket:soc1, data:'LIST /\r\n');
      result = ftp_recv_listing(socket:soc2);
      close(soc2);
    }
  }
  
  set_kb_item(name:"ftp/anonymous", value:TRUE);
  if(!get_kb_item("ftp/login"))
  {
    set_kb_item(name:"ftp/login", value:user);
    set_kb_item(name:"ftp/password", value:passwd);
  }

  if(result && strlen(result)) {
   desc += string("\nHere are the contents of the remote FTP directory listing:\n\n"); 
   desc += result;
   desc += string("\n");
  }
  log_message(port:port,data:desc);
}

close(soc1);
exit(0);
