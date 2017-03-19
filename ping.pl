use Socket;
use constant ICMP_ECHO_REQUEST => 8;

socket(SOCKET, AF_INET, SOCK_RAW, 255) || die $!;
setsockopt(SOCKET, 0, 1, 1);

#ojo, las variables $srcHost, $srcPort, $dstHost, $dstPort no estan definidas, ustedes las tienen que leer de la linea de comandos
my $packet = headers("192.168.0.1", 1, "173.194.215.113", 1);
my $destination = pack('Sna4x8', AF_INET, 1, "173.194.215.113");
$retVal = send(SOCKET,$packet,0,$destination);
print $retVal;

sub headers {
  local($srcHost,$srcPort,$dstHost,$dstPort) = @_;
  my $packet_id = int((rand(1000)));
  #type 8, code 8, checksum 16, id 16, sequence 16
  my $header = pack('ccnSs', ICMP_ECHO_REQUEST, 0,0, $id, 1);
  #sending 69 bytes
  my $data = "ICMP PROTOCOL HACK DATA ICMP PROTOCOL HACK DATA ICMP PROTOCOL HACK DATA";
  #calcular checksum del header + la data
  my $my_checksum = checksum($header.$data);
  $header = pack('ccnSsLL', ICMP_ECHO_REQUEST, 0, 3342, $id, 1, "192.168.0.37", "1");
  return $header.$data;
  #aqui tienen que hacer su magia
}

#para el calculo del checksum podrian usar una funcion como la siguiente:
sub checksum {
    my $msg = shift;
    my $length = length($msg);
    my $numShorts = $length/2;
    my $sum = 0;

    foreach (unpack("n$numShorts", $msg)) {
       $sum += $_;
    }

    $sum += unpack("C", substr($msg, $length - 1, 1)) if $length % 2;
    $sum = ($sum >> 16) + ($sum & 0xffff);
    return(~(($sum >> 16) + $sum) & 0xffff);
}


