# OpenVAS Vulnerability Test
# $Id: nmap.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Nmap (NASL wrapper)
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Slight changes by Vlatko Kosturjak <kost@linux.hr>
# Support for network level scans added by
# Michael Wiegand <michael.wiegand@greenbone.net>
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
tag_summary = "This plugin runs nmap to find open ports.";

# Nmap can be found at :
# <http://nmap.org>

if(description)
{
 script_id(14259);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 name = "Nmap (NASL wrapper)";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);

 summary = "Performs portscan / RPC scan";
 script_summary(summary);

 script_category(ACT_SCANNER);

 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
 family = "Port scanners";
 script_family(family);

 script_dependencies("toolcheck.nasl", "ping_host.nasl");

 v = pread(cmd: "nmap", argv: make_list("nmap", "-V"));
 if (v != NULL)
 {
  ver = ereg_replace(pattern: ".*nmap version ([0-9.]+).*", string: v, replace: "\1", icase: TRUE);
  if (ver == v) ver = NULL;
  }

 if (ver =~ "^[3-9]\.")
 script_add_preference(name:"TCP scanning technique :", type:"radio", 
  value:"connect();SYN scan;FIN scan;Xmas Tree scan;SYN FIN scan;FIN SYN scan;Null scan;No TCP scan");
 else
 script_add_preference(name:"TCP scanning technique :", type:"radio", 
  value:"connect();SYN scan;FIN scan;Xmas Tree scan;Null scan");

 # This preference has been dropped since OpenVAS 5 RC, so that port lists
 # entirely control whether UDP is scanned.
 split = split(OPENVAS_VERSION, sep:'.', keep:FALSE);
 if (int(split[0]) < 5)
   script_add_preference(name:"UDP port scan", type:"checkbox", value: "no");
 else if ((int(split[0]) == 5) && strstr(OPENVAS_VERSION, "beta"))
   script_add_preference(name:"UDP port scan", type:"checkbox", value: "no");
 script_add_preference(name:"Service scan", type:"checkbox", value: "no");
 script_add_preference(name:"RPC port scan", type:"checkbox", value: "no");
 script_add_preference(name:"Identify the remote OS", type:"checkbox", value: "no");
 script_add_preference(name:"Use hidden option to identify the remote OS", type:"checkbox", value: "no");
 script_add_preference(name:"Fragment IP packets (bypasses firewalls)", type:"checkbox", value: "no");
 if (ver !~ "3.7[05]")
 script_add_preference(name:"Get Identd info", type:"checkbox", value: "no");
 script_add_preference(name:"Do not randomize the  order  in  which ports are scanned", type:"checkbox", value: "no");
 script_add_preference(name: "Source port :", value: "", type: "entry");
 script_add_preference(name:"Timing policy :", type:"radio", value: "Normal;Insane;Aggressive;Polite;Sneaky;Paranoid;Custom");
 script_add_preference(name: "Host Timeout (ms) :", value: "", type: "entry");
 script_add_preference(name: "Min RTT Timeout (ms) :", value: "", type: "entry");
 script_add_preference(name: "Max RTT Timeout (ms) :", value: "", type: "entry");
 script_add_preference(name: "Initial RTT timeout (ms) :", value: "", type: "entry");
 script_add_preference(name: "Ports scanned in parallel (max)", value: "", type: "entry");
 script_add_preference(name: "Ports scanned in parallel (min)", value: "", type: "entry");
 script_add_preference(name: "Minimum wait between probes (ms)", value: "", type: "entry");
 script_add_preference(name: "File containing grepable results : ", value: "", type: "file");
 script_add_preference(name: 'Do not scan targets not in the file', value: 'no', type: 'checkbox');
 if (ver =~ "^3\.")
 script_add_preference(name: "Data length : ", value: "", type: "entry");
 script_add_preference(name: "Run dangerous port scans even if safe checks are set", value:"no", type:"checkbox");

 if(defined_func("script_mandatory_keys"))
  script_mandatory_keys("Tools/Present/nmap");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# script_mandatory_keys compatibility:
include ("toolcheck.inc");
exit_if_not_found (toolname: "nmap");
# end of script_mandatory_keys compatibility

include("host_details.inc");

# Check if this scanner supports scan phases
phase = 0;
if (defined_func("scan_phase"))
{
  phase = scan_phase ();
}

# Phases:
# 0: No network level scan requested or scanner does not support scan phases.
# 1: Network level scan requested, we need to scan network_targets instead
#    of the "real" target and need to store the results prefixed with IP.
# 2: Network level scan was requested and completed.
# If we already did a network level scan, the results are in the DB and
# there is no point in scanning this individual host again.
# Just read and report the results for this host.
if (phase == 2)
{
  ports = get_kb_list("Ports/tcp/*");
  foreach portstr (keys(ports))
  {
    port = split(portstr, sep:"/", keep:FALSE);
    scanner_add_port(proto:"tcp", port:port[2]);
  }
  exit(0);
}

tmpfile = NULL;

function on_exit()
{
  if (tmpfile && file_stat(tmpfile)) unlink(tmpfile);
}

function IP_IS_IPV6(ip) {

  if(":" >< ip) {
    return TRUE;
  }

  return FALSE;

}

safe_opt = script_get_preference("Run dangerous port scans even if safe checks are set");
if ( safe_opt && "yes" >< safe_opt ) safe = 0;
else safe = safe_checks();

if (phase == 0)
{
  ip = get_host_ip();
  esc_ip = ""; l = strlen(ip);
  for (i = 0; i < l; i ++) 
    if (ip[i] == '.') esc_ip = strcat(esc_ip, "\.");
    else esc_ip = strcat(esc_ip, ip[i]);
}
else
{
  ip = "network";
  esc_ip = "network";
}

res = script_get_preference_file_content("File containing grepable results : ");
res = egrep(pattern: "Host: +" + esc_ip + " ", string: res);
if (! res)
{
 opt = script_get_preference('Do not scan targets not in the file');
 if ('yes' >< opt) exit(0);

 i = 0;
 argv[i++] = "nmap";

 if(IP_IS_IPV6(ip:get_host_ip())) {
   argv[i++] = "-6";
 }

 argv[i++] = "-n";
 argv[i++] = "-P0";	# Nmap ping is not reliable
 argv[i++] = "-oG";

 tmpdir = get_tmp_dir();
 if (tmpdir && strlen(tmpdir)) {
   tmpfile = strcat(tmpdir, "nmap-", ip, "-", rand() );
   fwrite(data:" ",file:tmpfile); # make sure that tmpfile could be created. Then we can check that tmpfile exist with file_stat().
 }  

 if (tmpfile && file_stat(tmpfile))
  argv[i++] = tmpfile;
 else
  argv[i++] = "-";

 p = script_get_preference("TCP scanning technique :");
 if (p != "No TCP scan")
 {
  if (p == "SYN scan" || p == "SYN FIN scan") argv[i++] = "-sS";
  else if (p == "FIN scan" || p == "FIN SYN scan") argv[i++] = "-sF";
  else if (p == "Xmas Tree scan") argv[i++] = "-sX";
  else if (p == "Null scan") argv[i++] = "-sN";
  else argv[i++] = "-sT";
  if (p == "FIN SYN scan" || p == "SYN FIN scan")
  {
    argv[i++] = "--scanflags";
    argv[i++] = "SYNFIN";
  }
 }

 split = split(OPENVAS_VERSION, sep:'.', keep:FALSE);
 if ((int(split[0]) > 5)
     || ((int(split[0]) == 5) && !strstr(OPENVAS_VERSION, "beta")))
 {
  argv[i++] = "-sU";
 }

 # UDP & RPC scans or fingerprinting may kill a buggy IP stack
 if (! safe)
 {
  if (int(split[0]) < 5
      || ((int(split[0]) == 5) && strstr(OPENVAS_VERSION, "beta")))
  {
   p = script_get_preference("UDP port scan");
   if ("yes" >< p) argv[i++] = "-sU";
  }
  p = script_get_preference("Service scan");
  if ("yes" >< p) argv[i++] = "-sV";
  p = script_get_preference("RPC port scan");
  if ("yes" >< p) argv[i++] = "-sR";
  p = script_get_preference("Identify the remote OS");
  if ("yes" >< p) argv[i++] = "-O";
  p = script_get_preference("Use hidden option to identify the remote OS");
  if ("yes" >< p) argv[i++] = "--osscan_guess";
  p = script_get_preference("Fragment IP packets (bypasses firewalls)");
  if ("yes" >< p) argv[i++] = "-f";
 }
 p = script_get_preference("Get Identd info");
 if ("yes" >< p) argv[i++] = "-I";
 port_range = get_preference("port_range");
 if (port_range) # Null for command line tests only
 {
  argv[i++] = "-p";
  if (port_range == "default" )
  {
   n = 0;
   str = "";
   while ( port = scanner_get_port(n) )
   {
    if ( n > 0 ) str += "," + string(port);
    else str = string(port);
    n ++;
   }
   argv[i++] = str;
  }
  else
   argv[i++] = port_range;
  }
 
 p = script_get_preference("Do not randomize the  order  in  which ports are scanned");
 if ("yes" >< p) argv[i++] = "-r";
 p = script_get_preference("Source port :");
 if (p =~ '^[0-9]+$') { argv[i++] = "-g"; argv[i++] = p; }

 p = get_preference("source_iface");
 if (p =~ '^[0-9a-zA-Z:_]+$') { argv[i++] = "-e"; argv[i++] = p; }

 # We should check the values when running in "safe checks".
 custom_policy = 0;
 p = script_get_preference("Host Timeout (ms) :");
 if (p =~ '^[0-9]+$')
 {
   argv[i++] = "--host_timeout";
   argv[i++] = p;
   custom_policy ++;
 }
 p = script_get_preference("Min RTT Timeout (ms) :");
 if (p =~ '^[0-9]+$')
 {
   argv[i++] = "--min_rtt_timeout";
   argv[i++] = p;
   custom_policy ++;
 }
 p = script_get_preference("Max RTT Timeout (ms) :");
 if (p =~ '^[0-9]+$')
 {
   argv[i++] = "--max_rtt_timeout";
   argv[i++] = p;
   custom_policy ++;
 }
 p = script_get_preference("Initial RTT Timeout (ms) :");
 if (p =~ '^[0-9]+$')
 {
   argv[i++] = "--initial_rtt_timeout";
   argv[i++] = p;
   custom_policy ++;
 }
 min = 1;
 p = script_get_preference("Ports scanned in parallel (min)");
 if (p =~ '^[0-9]+$')
 {
   argv[i++] = "--min_parallelism";
   argv[i++] = p;
   min = p;
   custom_policy ++;
 }
 p = script_get_preference("Ports scanned in parallel (max)");
 if (p =~ '^[0-9]+$')
 {
   argv[i++] = "--max_parallelism";
   if (p < min) p = min;
   argv[i++] = p;
   custom_policy ++;
 }

 p = script_get_preference("Minimum wait between probes (ms)");
 if (p =~ '^[0-9]+$')
 {
   argv[i++] = "--scan_delay";
   argv[i++] = p;
   custom_policy ++;
 }

 if (! custom_policy)
 {
   timing_templates = make_array(
                        "Paranoid", 0,
                        "Sneaky", 1,
                        "Polite", 2,
                        "Normal", 3,
                        "Aggressive", 4,
                        "Insane", 5);

   p = script_get_preference("Timing policy :");
   if (isnull(p))
     p = "Normal";
   timing = timing_templates[p];
   if (!isnull(timing)) {
     argv[i++] = "-T";
     argv[i++] = timing;
   }
 }

 p = script_get_preference("Data length : ");
 if (p =~ '^[0-9]+$')
 {
   argv[i++] = "--data_length";
   argv[i++] = p;
   custom_policy ++;
 }

 if (phase == 1)
   argv[i++] = network_targets ();
 else
   argv[i++] = ip;

scanner_status(current: 0, total: 65535);
 res = pread(cmd: "nmap", argv: argv, cd: 1);

 if (tmpfile && file_stat(tmpfile))
  res = fread(tmpfile);
# display(argv, "\n", res, "\n\n");
 if (! res) exit(0);	# error
}

if (phase == 0)
{
  if (egrep(string: res, pattern: '^# +Ports scanned: +TCP\\(65535;'))
    full_scan = 1;
  else
   full_scan = 0;

  res = egrep(pattern: "Host: +" + esc_ip + " ", string: res);
  if (! res)
  {
   mark_dead = get_kb_item("/ping_host/mark_dead");
   if("yes" >< mark_dead) {
     set_kb_item(name: "Host/ping_failed", value: 1);
   }
   exit(0);
  }

  res = ereg_replace(pattern: 'Host: +[0-9.]+ .*[ \t]+Ports: +',
                     string: res, replace: "");
  # Fields:
  # port_nb/state/protocol/owner/port_name/rpc_name/service/
  # Example:
  # Host: 127.0.0.1 ()      Ports: 111/open/tcp/bin/rpcbind (rpcbind V2)/(rpcbind:100000*2-2)/2 (rpc #100000)/, 111/open/udp//rpcbind (rpcbind V2)/(rpcbind:100000*2-2)/2 (rpc #100000)/, 113/open/tcp/root/ident //Linux-identd/, 119/open/tcp/root/nntp //Leafnode NNTPd 1.9.49.rel/, 123/open/udp//ntp ///, 137/open/udp//netbios-ns //Samba nmbd (host: CASSEROLE workgroup: MAISON)/, 138/open/udp//netbios-dgm ///, 139/open/tcp/root/netbios-ssn //Samba smbd 3.X (workgroup: MAISON)/      Ignored State: closed (194)

  scanned = 0; udp_scanned = 0; ident_scanned = 0;
  foreach blob(split(res, sep: ',', keep:0))
  {
    v = eregmatch(string: blob, icase: 1,
    pattern: "^(Host: .*:)? *([0-9]+)/([^/]+)/([^/]+)/([^/]*)/([^/]*)/([^/]*)/([^/]*)/?");
    if (! isnull(v))
    {
     port = v[2];
     status = v[3];
     proto = v[4];
     owner = v[5];
     svc = v[6];
     rpc = v[7];
     ver = v[8];
  # display("port=", port, "\nstatus=", status, "\nproto=", proto, "\nsvc=", svc, "\nowner=", owner, "\nrpc=", rpc, "\nver=", ver, "\n\n");
     if ("open" >< status)	# nmap 3.70 says "open|filtered" on UDP
       scanner_add_port(proto: proto, port: port);
      if (owner)
      {
        log_message(port: port, proto: proto, data: "This service is owned by user "+owner);
        set_kb_item(name: "Ident/"+proto+"/"+port, value: owner);
        ident_scanned ++;
      }
      scanned ++;
      if (proto == "udp") udp_scanned ++;
      if (strlen(rpc) > 1)
      {
        r = ereg_replace(string: rpc, pattern: "\(([^:]+):.+\)", replace: "\1");
        if (! r) r = rpc;
        log_message(port: port, proto: proto, 
         data: "The RPC service "+r+" is running on this port
If you do not use it, disable it, as it is
a potential security risk");
      }
      if (ver)
      {
        ver = ereg_replace(pattern: "^([0-9-]+) +\((.+)\)$", string: ver,
                           replace: "\2 V\1");
        log_message(port: port, proto: proto, data: "Nmap has identified this service as " + ver);
        set_kb_item(name: 'Nmap/'+proto+'/'+port+'/version', value: ver);
        if (string !~ "\?$")
         set_kb_item(name: 'Nmap/'+proto+'/'+port+'/svc', value: svc);
        # set_kb_item(name: "NmapSvc/"+port, value: svc);
      }
   }
  }

  v = eregmatch(string: res, pattern: 'OS: ([^\t]+)');
  if (! isnull(v))
  {
    log_message(port: 0, data: "Nmap found that this host is running "+v[1]);
    set_kb_item(name: "Host/OS", value: v[1]);
    register_host_detail(name:"OS", value:v[1], nvt:"1.3.6.1.4.1.25623.1.0.14259",
      desc:"Performs portscan / RPC scan");
  }

  v = eregmatch(string: res, pattern: 'Seq Index: ([^\t]+)');
  if (! isnull(v))
  {
    idx = int(v[1]);
    if (idx == 9999999)
    {
      log_message(port: 0, data: "The TCP initial sequence number of the remote host look truely random. 
Excellent!");
      set_kb_item(name: "Host/tcp_seq", value: "random");
     }
    else if (idx == 0)
    {
      set_kb_item(name: "Host/tcp_seq", value: "constant");
    }
    else if (idx == 1)
    {
      set_kb_item(name: "Host/tcp_seq", value: "64000");
    }
    else if (idx == 10)
    {
      set_kb_item(name: "Host/tcp_seq", value: "800");
    }
    else if (idx < 75)
    {
      set_kb_item(name: "Host/tcp_seq", value: "time");
    }
    else
    {
      log_message(port: 0, data: "The TCP initial sequence number of the remote host are incremented by random positive values. 
Good!");
      set_kb_item(name: "Host/tcp_seq", value: "random");
     }
    set_kb_item(name: "Host/tcp_seq_idx", value: v[1]);
  }

  v = eregmatch(string: res, pattern: 'IPID Seq: ([^\t]+)');
  if (! isnull(v))
    log_message(port: 0, data: "the IP ID sequence generation is: " + v[1]);

  if (scanned)
  {
   set_kb_item(name: "Host/scanned", value: TRUE);
   set_kb_item(name: 'Host/scanners/nmap', value: TRUE);
  }
  if (udp_scanned) set_kb_item(name: "Host/udp_scanned", value: TRUE);
  if (full_scan)
  {
   if (ident_scanned) set_kb_item(name: "Host/ident_scanned", value: TRUE);
   set_kb_item(name: "Host/full_scan", value: TRUE);
  }
}
else if (phase == 1)
{
 lines = split (res, sep: '\n', keep: FALSE);
 foreach blob (lines)
 {
    c = split(blob,sep:"Ports: ", keep: FALSE);
    d = split(c[0],sep:" ", keep: FALSE);
    e = split(c[1],sep:", ", keep: FALSE);
    if (! isnull (e))
    {
      foreach f (e)
      {
        g = split (f, sep:"/", keep: FALSE);
        set_kb_item(name: d[1] + "/Ports/tcp/" + g[0], value: 1);
      }
    }
  }
}

scanner_status(current: 65535, total: 65535);
