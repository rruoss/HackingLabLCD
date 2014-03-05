# OpenVAS Vulnerability Test
# $Id: netstat_portscan.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Netstat 'scanner'
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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
tag_summary = "This plugin runs netstat on the remote machine to find open ports.";

if(description)
{
 script_id(14272);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "Netstat 'scanner'";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Find open ports with netstat";
 script_summary(summary);
 
 script_category(ACT_SCANNER);
 
 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
 family = "Port scanners";
 script_family(family);
 script_dependencies("ping_host.nasl","ssh_authorization.nasl");
 script_mandatory_keys("login/SSH/success");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
include("ssh_func.inc");

buf = "";

# On the local machine, just run the command
if (islocalhost())
  buf = pread(cmd: "netstat", argv: make_list("netstat", "-a", "-n"));
else
{
# First try the netstat service, just in case
 s = open_sock_tcp(15);
 if (s)
 {
   while (r = recv(socket: s, length: 4096))
     buf += r;
   close(s);
 }
# Then try SSH if the result is not OK
 if ("LISTEN" >!< buf)
 {
 sock = ssh_login_or_reuse_connection();
 if (! sock)  exit(0);

 buf = ssh_cmd(socket:sock, cmd:"cmd /c netstat -an", timeout:60);

 if ("LISTENING" >!< buf && "0.0.0.0:0" >!< buf && "*.*" >!< buf)
 {
 buf = ssh_cmd(socket:sock, cmd:"netstat -a -n", timeout:60);
 ssh_close_connection();
 if (! buf) { display("could not send command\n"); exit(0); }
 }
}
}

# display(buf);
ip = get_host_ip();
lines = split(buf);
n = max_index(lines);
if (n == 0) n = 1; i = 0;
scanner_status(current: 0, total: n);
scanned = 0;
check = 
 (! safe_checks()) ||
 ("yes" >< get_kb_item("global_settings/experimental_scripts_tests")) ||
 ("yes" >< get_preference("unscanned_closed")) ||
 ("yes" >< get_kb_item("global_settings/thorough_tests"));
# ("Avoid false alarms" >< get_kb_item("global_settings/report_paranoia"))

identd_n = 0; identd_err = 0;

foreach line (lines)
{
  # Windows
  v = eregmatch(pattern: '^[ \t]+(TCP|UDP)[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):([0-9]+)[ \t]+(0\\.0\\.0\\.0:0|\\*\\.\\*)[ \t]+', string: line, icase: 0);
  # Unix
  if (isnull(v))
   v = eregmatch(pattern: '^(tcp|udp)[46]?[ \t]+.*[ \t]+(\\*|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)[:.]([0-9]+)[ \t]+(.*[ \t]+LISTEN|0\\.0\\.0\\.0:\\*)', string: line, icase: 1);
  if (isnull(v))
  # tcp 0 0 :::22   :::*    LISTEN
  # tcp 0 0 ::1:25  :::*    LISTEN (1 = localhost)
  v = eregmatch(pattern: '^(tcp|udp)[ \t]+.*[ \t]+(:::)([0-9]+)[ \t]+.*[ \t]+LISTEN', string: line, icase: 1);

  # Solaris 9
  if (isnull(v))
  {
    if (last_seen_proto)
    {
      if (last_seen_proto == 'udp')
        v = eregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+Idle', string: line);
      else
        v = eregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+\\*\\.\\*[ \t]+.*(Idle|LISTEN)', string: line);
      
      if (! isnull(v))
      {
        # "Fix" array
        v[3] = v[2]; v[2] = v[1]; v[1] = last_seen_proto;
      }
    }
    if (isnull(v))
    {
      v = eregmatch(pattern: '^(TCP|UDP): +IPv4[ \t\r\n]*$', string: line);
      if (!isnull(v))
      {
        last_seen_proto = tolower(v[1]);
        v = NULL;
      }
    }
  }
  

  if (!isnull(v))
  {
    if (check)
      identd_soc = open_sock_tcp(113);
    proto = tolower(v[1]);
    addr = v[2];
    port = v[3];
    # display("> ", addr, ":", port, " (", proto, ")\n");
    if (int(port) < 1 || int(port) > 65535)
     display('netstat_portscan(', get_host_ip(), '): invalid port number ', port, '\n');
    else if ((check && addr != "127.0.0.1") || 
        addr == "0.0.0.0" || addr == ip || addr == ":::" || addr == '*')
    {
      if (check && proto == "tcp")
      {
        soc = open_sock_tcp(port);
        if (soc)
        {
          scanner_add_port(proto: proto, port: port);
	  if (identd_soc)
	  {
	    req = strcat(port, ',', get_source_port(soc), '\r\n');
	    if (send(socket: identd_soc, data: req) <= 0)
	    {
	      # Let's be quick: do not reopen the socket if an error occurs
	      # Another plugin with complete the job
	      close(identd_soc);
	      identd_soc = NULL;
	      identd_err ++;
	      id = NULL;
	    }
	    else
	      id = recv_line(socket: identd_soc, length: 1024);
	    if (id)
	    {
	      ids = split(id, sep: ':');
	      if ("USERID" >< ids[1])
              {
		identd_n ++;
		set_kb_item(name: "Ident/tcp/"+port, value: ids[3]);
		security_note(port: port, 
data: 'identd reveals that this service is running as user '+ids[3]);
	      }
	    }
	  }
          close(soc);
        }
      }
      else
      scanner_add_port(proto: proto, port: port);
      # display(proto, "\t", port, "\n");
    }
    scanned ++;
  }
  scanner_status(current: i++, total: n);
}

if (identd_soc) close(identd_soc);

if (scanned)
{
 set_kb_item(name: "Host/scanned", value: TRUE);
 set_kb_item(name: "Host/udp_scanned", value: TRUE);
 set_kb_item(name: "Host/full_scan", value: TRUE);
 set_kb_item(name: 'Host/scanners/netstat', value: TRUE);
 if (identd_n && ! identd_err)
   set_kb_item(name: "Host/ident_scanned", value: TRUE);
}

scanner_status(current: n, total: n);
exit(0);
