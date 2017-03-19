#!/usr/local/bin/perl

use Socket;
use constant ICMP_ECHO_REQUEST => 8;
#print "Enter destination port: ";
#my $dstHost = <STDIN>; #get input from cmd
#print $dstHost;

#my $srcPort = '127.0.0.1';
#my $srcHost = 'localhost';
#my $dstHost = 'google.com';


#a short integer in network order
#ASCII character string padded with null characters

#para el calculo del checksum podrian usar una funcion como la siguiente:
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

#print checksum('test');

sub doPing {
    my $dest_addr = shift;
    my $timeout = shift;

    socket(SOCKET, AF_INET, SOCK_RAW, 1) || die $!;
    setsockopt(SOCKET, 0, 1, 1);

    my $packet_id = int(($timeout * rand(1000)));
    
    my $packet = create_packet($packet_id);
    print $packet;
    my $destination = pack('Sna4x8', AF_INET, 1, $dest_addr);


    my $sent = send(SOCKET,$packet,0,$destination);
    print $sent;
    #print $packet;

    

}

sub ntohs
{
    return pack("S", unpack("n", $_[0]));
}


sub htons
{
    return ntohs(@_);
}

sub create_packet {
    my $id = shift;
    #signed char, signed char, unsigned short, unsigned short, short 
    #ccSSs
    #type 8, code 8, checksum 16, id 16, sequence 16
    my $header = pack('ccnSs', ICMP_ECHO_REQUEST, 0,0, $id, 1);
    #sending 69 bytes
    my $data = "ICMP PROTOCOL HACK DATA ICMP PROTOCOL HACK DATA ICMP PROTOCOL HACK DATA";
    #calcular checksum del header + la data
    my $my_checksum = checksum($header.$data);
    $header = pack('ccnSsLL', ICMP_ECHO_REQUEST, 0, $my_checksum, $id, 1, "192.168.0.37", "1");
    print $id." identifier \n";
    print $my_checksum."\n";
    print ICMP_ECHO_REQUEST."\n";
    return $header.$data;
}
doPing("google.com", 3);
#print ICMP_ECHO_REQUEST;