#UVG Pablo Díaz 19/03/2017
#references used:
#https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
#https://en.wikipedia.org/wiki/IPv4
#http://www.perlmonks.org/?node_id=1101500
#http://www.perlmonks.org/?displaytype=displaycode;part=1;node_id=17576;abspart=1
#http://www.catonmat.net/download/perl.pack.unpack.printf.cheat.sheet.pdf
#https://www.tutorialspoint.com/perl/perl_pack.htm
#http://perldoc.perl.org/functions/pack.html
#https://es.wikipedia.org/wiki/Internet_Control_Message_Protocol#Echo_Reply
use Socket;
#use Time::HiRes;
use constant ICMP_ECHO_REQUEST => 8;
use Sys::Hostname; #to get local ip
use Time::HiRes qw( gettimeofday tv_interval);


#$src_host = $ARGV[0]; # The source IP/Hostname
#$src_port = $ARGV[1]; # The Source Port
$dst_host = $ARGV[0]; # The Destination IP/Hostname
#$dst_port = $ARGV[3]; # The Destination Port.

if(!defined $dst_host) {
    # print usage instructions
    print "Usage: $0 <dest host> \n";
    exit;
} 
else {
    # call the main function
    main();
}
  
sub main {
    my $src_host = (gethostbyname($src_host))[4];
    my $destination_host = (gethostbyname($dst_host))[4];
    
    # when IPPROTO_RAW is used IP_HDRINCL is not needed
    $IPROTO_RAW = 1;
    socket(SOCKET , AF_INET, SOCK_RAW, $IPROTO_RAW) 
        or die $!;
     
    #set IP_HDRINCL to 1, this is necessary when the above protocol is something other than IPPROTO_RAW
    #setsockopt(SOCKET, 0, IP_HDRINCL, 1);
    my $src_host = inet_ntoa((gethostbyname(hostname))[4]);
    my $ip_host = inet_ntoa(inet_aton($dst_host));
    my $src_port = 1; #doesnt matter
    my $dst_port = 1; #doestn matter
    my $id = int(rand(100000));
    my $packet = makeheaders($src_host, $src_port, $ip_host, $dst_port, $id);
     
    my $destination = pack('Sna4x8', AF_INET, $dst_port, $destination_host);
    
    $cont = 0;
    print "PING " . $dst_host . " (" . $ip_host . ")" . ": " . length($packet) . " data bytes \n";
    while ($cont < 10) {
        my $timer = tv_interval ( $t0, [gettimeofday]);
        my $sent_bytes = send(SOCKET , $packet , 0 , $destination) or die $!;
        #print "PING " . $dst_host . " (" . $ip_host . ")" . ": " . $sent_bytes . " data bytes \n";
        my $my_message;
        my $rtime = "";
        my $buf = "";
        
        #saves the data received
        my $received_bytes = sysread(SOCKET, $buf, 1024, 0);    
        # this only receives de socket and the host, no data
        #my $hispaddr = recv(SOCKET, $rtime, $sent_bytes, 1024)    || die "recv: $!";
       
        $icmpHeader = $buf;
        #print $icmpHeader . " buffer \n";
        #type, code, checksum, p_id, sequence
        @array = unpack(
             "SSSSSSSSSSccnSs", $buf
        );
        #print $array[10] . " type \n";
        #print $array[11] . " code \n";
        #print $array[12] . " checksum\n";
        #print $array[13] . " id\n";
        #print $array[14] . " sequence \n";
        $verify_id = $array[13];
        if ($verify_id == $id) {

            my $now_time = tv_interval ( $t0, [gettimeofday]) - $timer;
            my $RRT = substr($now_time*1000, 0, 5);
            my $RRT2 = $RRT/2;
            print $received_bytes . " bytes from " . " (".$ip_host. ") "." RTT " . $RRT . " ms "  . " RTT/2 " . $RRT2 . " ms \n";
            $cont = $cont + 1;

            sleep(1);
        } else {
            #print "ruido \n";
        }
        
        #my ($port, $hisiaddr) = sockaddr_in($hispaddr);
        # my $host = gethostbyaddr($hisiaddr, AF_INET);
        
        # #print $prt
        # #print $host . "host\n";
        # #print gethostbyaddrtbyname($host)."\n";
        # #print inet_ntoa(inet_aton(($host)))."\n";
        # if (length($host) == 0) {
        #     print "Request timeout \n";
        # } else {
        #     my $histime = unpack("N", $rtime);
        #     $RRT = substr($now_time*1000, 0, 5);
        #     $RRT2 = $RRT/2;
        #     my $receive_ip = inet_ntoa(inet_aton($host));
        #     print "time " . $histime . "\n";
        #     if ($receive_ip eq $ip_host) {
        #         print $sent_bytes . " bytes from " . $host . " (".$receive_ip. ") "." RTT " . $RRT . " ms "  . " RTT/2 " . $RRT2 . " ms \n";
        #     } else {
        #         print "different ip received \n";
        #     }
        # }
        
        #printf "%8d %s\n", $histime - time(), scalar localtime($histime) ;
        #$RRT = substr($now_time*1000, 0, 5);

       
    }
    #my $my_time = gettimeofday;
    #print qq|$time{'yyymmdd hh:mm:ss.mmm', $time}\n\

    
}
 
sub makeheaders {
    $IPPROTO_TCP = 1;
    local($src_host , $src_port , $dst_host , $dst_port, $id) = @_;
     
    my $zero_cksum = 0;
    # Lets construct the ICMP half
    my $icmp_header = pack('ccSSs', ICMP_ECHO_REQUEST, 0,0, $id, 1);
    #sending 48 bytes
    my $data = "UNIVERSIDAD DEL VALLE DE GUATEMALA ICMP DIA13203";
    #calcular checksum del icmp_header + la data
    my $my_checksum = checksum($icmp_header.$data);
    #should invert checksum
    #my $reverse_checksum = pack("S", unpack("n", $my_checksum));
    print $id ." id sent\n";
    $icmp_header = pack('ccnSs', ICMP_ECHO_REQUEST, 0, ($my_checksum), $id, 1);

    # construct IP package
    my $ip_ver = 4;
    my $ip_len = 5;
    my $ip_ver_len = $ip_ver . $ip_len;
     
    my $ip_tos = 00;
    my $ip_tot_len = length($header . $data) + 20;
    my $ip_frag_id = 19245;
    my $ip_ttl = 25;
    my $ip_proto = $IPPROTO_TCP;    # 1 for icmp
    my $ip_frag_flag = "000";
    my $ip_frag_oset = "0000000000000";
    my $ip_fl_fr = $ip_frag_flag . $ip_frag_oset;

    #$src_host = ip2bin($src_host, '');
    #$dst_host = ip2bin($dst_host, '');
    # ip header
    # src and destination should be a4 and a4 since they are already in network byte order
    my $ip_header = pack('H2CnnB16CCna4a4', 
        $ip_ver_len, $ip_tos, $ip_tot_len, 
        $ip_frag_id, $ip_fl_fr , $ip_ttl , $ip_proto , 
        $zero_cksum , $src_host , $dst_host);
     
    # ip_header + header_icmp + data;
    # tested with ip header and it doesnt work.
    my $pkt =  $icmp_header . $data;
    #my $pkt = $ip_header . $header . $data;
     
    # packet is ready
    return $pkt;
}
 
 
#para el calculo del checksum podrian usar una funcion como la siguiente
sub checksum {
    my $msg = shift;
    #print $msg;
    my $length = length($msg);
    #print $length;
    my $numShorts = $length/2;
    my $sum = 0;

    foreach (unpack("n$numShorts", $msg)) {
       $sum += $_;
    }    #returns list of unsigned characters of 8 bytes

    $sum += unpack("C", substr($msg, $length - 1, 1)) if $length % 2;
    $sum = ($sum >> 16) + ($sum & 0xffff);
    return(~(($sum >> 16) + $sum) & 0xffff);
} 

sub ip2bin{
    my ($ip, $delimiter) = @_;
    return     join($delimiter,  map 
        substr(unpack("B32",pack("N",$_)),-8), 
        split(/\./,$ip));
}
