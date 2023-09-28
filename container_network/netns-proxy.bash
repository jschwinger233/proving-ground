# $ns, $ip, $veth
set -x
ip net a $ns
ip l a $veth type veth peer name $veth-peer
ip l s $veth-peer up
ip l s $veth netns $ns
ip net e $ns ip l s $veth up
ip net e $ns ip a a $ip dev $veth
ip net e $ns ip r a 169.254.0.1 dev $veth
ip net e $ns ip r a default via 169.254.0.1 dev $veth
ip r a $ip dev $veth-peer
