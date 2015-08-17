#! /usr/bin/perl

#
# Filtre des mails de signalement de incidents securite
#
# Ce programme est appele par le mailer ; il decompose
# un message et analyse l'attachement xml s'il existe
#

use Email::MIME;
use XML::Simple;
use DBI;
use Net::LDAP;
use Net::LDAP::Constant qw{LDAP_SUCCESS};

use Time::ParseDate;
use Time::Simple;

use RT;
use RT::Ticket;
use RT::Interface::CLI qw(CleanEnv);

use strict;
use warnings;
use utf8;

#
# Variables
#

# Acces a la base netmagis
my $dbhost_netmagis="%NETMAGIS_HOST%";
my $dbname_netmagis="%NETMAGIS_DATABASE%";
my $dbuser_netmagis="%NETMAGIS_USER%";
my $dbpass_netmagis="%NETMAGIS_PW%";

our $dbd_netmagis;

# Acces a la base mac
my $dbhost_mac="%MAC_HOST%";
my $dbname_mac="%MAC_DATABASE%";
my $dbuser_mac="%MAC_USER%";
my $dbpass_mac="%MAC_PW%";

our $dbd_mac;

# Acces a l'annuaire
my $ldapurl = '%LDAPHOST';
my $ldapbinddn = '%LDAPBINDDN%';
my $ldapbindpw = '%LDAPPASS%';

our $ldapbase = '%LDAPBASE%';
our $ldap;

# Webservice
our $block_create_app = '%BLOCKCREATEURL%';
our $block_run_app = '%BLOCKRUNURL%';

# Format du message envoi
our $msgtempl = "Bonjour,

Ceci est un message du CERT Osiris.

Un incident sécurité a été ouvert.

%PB%

Les détails de l'incident sont consignés en piece jointe.

Merci de faire le necessaire.

Cordialement,

--
Le CERT Osiris
";

#
# Motifs: adresses IP
#

our @addresspattern = ('130\.79\.[0-9]+\.[0-9]+');

#
# Procedures
#

sub handle_message {
	my $message = shift;

	my %incident_data = ();
	my $found = 0;
	my $parsed = Email::MIME->new($message);
	my @parts = $parsed->parts; 
	my $ticket;

	#
	# 1er passage :
	# Analyse le contenu de l'attachement s'il est au format xml
	#
	foreach my $part (@parts) {
		if ($part->content_type =~ m,application/xml,i) {
			#
			# Analyse les balises xml
			#
			$found = sec_parse($part->body, \%incident_data);
		}
	}

	#
	# 2eme passage:
	# Analyse le contenu en l'absence d'attachement XML
	# si rien n'a ete trouve precedemment
	#

	if (! $found) {

		# S'il n'y a pas d'attachement XML, chercher un motif
		# correspond a une adresse IP dans le corps du message ou dans le sujet
		# NB : les informations manquantes doivent pouvoir etre completees
		# par la suite via des interfaces de recherche (mac, login wifi/vpn etc.)

		foreach my $part (@parts) {
			if ($part->content_type =~ m,text/plain,i) {
				$found = look_for_address($part->body, \%incident_data);
			}
		}
	}


	#
	# Creer le ticket vide
	#

	$ticket = create_ticket_sec(\%incident_data, @parts);
	
	#
	# Correspondants -> ajout en demandeur 
	#

	add_correspondant($ticket, \%incident_data);
	
	#
	# Envoi d'un message au correspond avec toutes les
	# informations necessaires
	#

	send_msg_correspondant($ticket, \%incident_data, $message);

	#
	# Genere une commande de filtrage/defiltrage sous forme
	# de lien cliquable
	#
	
	gen_filter_att($ticket, $incident_data{ip});
}

#
# Cree le ticket
#
sub create_ticket_sec {
	my ($ref, @parts) = @_;

	my %ticket_vals;

	$ticket_vals{'Queue'} = 'Cert';

	# Si l'adresse IP est connue, on l'indique dans sujet
	my $addsubj = "";
	if ($ref->{ip}) {
		$addsubj = " sur la machine " . $ref->{ip};
	}

	$ticket_vals{'Subject'} = "Incident Securite" . $addsubj;

	my $TicketObj = RT::Ticket->new($RT::SystemUser);

	$TicketObj->Create(%ticket_vals);

	# Ajoute les differentes parties du message
	my $mimeobj = MIME::Entity->build(Type => "multipart/mixed");
	foreach my $part (@parts) {
		# Attache la partie
		$mimeobj->attach(Type => $part->content_type, Data => $part->body);
	}

	# Cree la premiere transaction avec le message
	$TicketObj->Correspond( MIMEObj => $mimeobj );

	return $TicketObj;
}

#
# Modifie les demandeurs pour y ajouter les correspondants
# et envoie une réponse
#
sub add_correspondant {
	my ($ticket,$ref) = @_ ; 

	# Pour chaque correspondant

	foreach my $mail (keys %{ $ref->{corresp} } ) {
		$ticket->AddWatcher( Type => 'Requestor', Email => $mail);
	}
}

#
# Modifie les demandeurs pour y ajouter les correspondants
# et envoie une réponse
#
sub send_msg_correspondant {
	my ($ticket,$ref,$origmessage) = @_ ; 

	#
	# TODO : cas des incidents qui ne concerne pas des machines
	#
	my $pb = "";
	if ($ref->{ip}) {
		$pb = "Il concerne la machine " . $ref->{ip} . "\n";
	}
	if ($ref->{mac}->{address}) {
		$pb = "(adresse mac : " . $ref->{mac}->{address} . ")\n";
	}
    if ($ref->{typeincident}) {
		# TODO : decrire l'incident dans un langage comprehensible
		$pb .= "La nature de l'incident est : " . $ref->{typeincident} . "\n";
	}
	if ($ref->{datetime}) {
		$pb .= "L'incident a commencé le : " .
					timet2readabledate(date2timet($ref->{datetime})) . "\n";
	}

	my $msg = $msgtempl;
	$msg =~ s/%PB%/$pb/;

	#
	# Construit le message
	#
	my $mimeobj = MIME::Entity->build(Type => "multipart/mixed");

	# Attache le texte
	$mimeobj->attach(Type => 'text/plain', Data => $msg);

	# Attache le message original
	$mimeobj->attach(Type => 'message/rf822', Data => $origmessage);

	# Envoi le message
	$ticket->Correspond( MIMEObj => $mimeobj);

	# Ajoute la categorie 
	if ($ref->{typeincident}) {
		my $nom_categ = $ref->{typeincident};
		# Ajoute la categorie d'incident
		my $Cf = RT::CustomField->new($RT::SystemUser);
		$Cf ->Load ("TypeIncidentSec");
		$ticket->AddCustomFieldValue(Field => $Cf->Id, Value => $nom_categ);
	}
}

#
# Genere un lien de filtrage/defiltrage
#
sub gen_filter_att {
	my ($ticket, $ip) = @_ ;

	# Appel du webservice pour generer un lien de filtrage
	my $idticket = $ticket->id;
	my $url =  $block_create_app ."/create/$idticket/$ip";
	my $hash = "";
	open(PAGE, "/usr/bin/curl --raw --silent $url |");
	$hash = <PAGE>;
	close(PAGE);

    if ($hash !~ /^[a-f0-9]+$/) {
        # FIXME : traiter le cas d'erreur
        die "erreur curl $url";
    }

	# Generer le lien
    my $block = $block_run_app . "/filter/$hash" ;
    my $unblock = $block_run_app . "/unfilter/$hash" ;

	# Ajout d'un commentaire au ticket avec les liens

    my $msg = "Pour filtrer l'adresse $ip : <A HREF=\"$block\">$block</A>\n" .
			  "<BR><BR>" .
              "Pour défiltrer l'adresse $ip : <A HREF=\"$unblock\">$unblock</A>\n" ;

	my $mimeobj = MIME::Entity->build(Type => "multipart/mixed");

	# Attache le texte
	$mimeobj->attach(Type => 'text/html', Data => $msg);

	# Envoi le message
	$ticket->Correspond( MIMEObj => $mimeobj);

}

#
# Retourne vrai si l'adresse correspond a un reseau wifi interne
#
sub is_wifi {
	my $ip = shift;

	# Reseau
	my $is_wifi = 0;
	my $sql="SELECT * FROM dns.reseau r, dns.communaute c
				WHERE r.adr4 >> '$ip'
					AND c.idcommu=r.idcommu AND c.nom='IP privées Wifi'";
	my $cursor = $dbd_netmagis->prepare($sql);
	$cursor->execute;
	if ($cursor->fetchrow)  {
		$is_wifi = 1;
	}
	$cursor->finish;

	return $is_wifi;
}

#
# Collecte les informations a partir des balises XML
#
# Valeur de retour : 1 si une adresse IP ou un compte
# a ete trouvée et 0 si rien n'a ete trouve
#
# TODO : cas des incidents qui ne concerne pas des machines
#
sub sec_parse {
	my ($content, $incident_data) = @_;


	# conserve le source xml pour reference
    $incident_data->{xml} = $content;

	my $xmltree = XMLin($content);

	# Description -> champ personnalise "categorie incident securite"
    $incident_data->{ip} = $xmltree->{Incident}->{Attack}->{Source}->{SourceIP};

	# Identifiant de l'incident
    $incident_data->{id} = $xmltree->{Incident}->{IncidentId};

    $incident_data->{typeincident} = $xmltree->{Incident}->{Attack}->{Description};
    $incident_data->{datetime} = $xmltree->{Incident}->{Attack}->{StartTime};

	# Reecris l'adresse ip en adresse interne si necessaire
	trans_addr($incident_data->{ip}, $incident_data->{datetime}, $incident_data);

	# Adresse ip -> nom et adresse du sous-reseau,
	#					email des correspondants
	locate_address($incident_data->{ip}, $incident_data);

	#	ip, heure -> recherche adresse mac
	get_mac($incident_data->{ip}, $incident_data->{datetime}, $incident_data);

	# TODO : rechercher l'equipement reseau, port, vlan corresp. a l'adresse mac

	# (si le reseau correspond au wifi)
	#		mac, heure -> recherche du login
	if(is_wifi($incident_data->{ip})) {
		get_login_wifi($incident_data->{mac}->{address},
				 $incident_data->{datetime}, $incident_data);
	}

	if($incident_data->{ip} ne "" || $incident_data->{uid} ne "") {
		return 1;
	} else {
		return 0;
	}
}

#
# Recherche les informations a partir des balises XML
#
# Valeur de retour : 1 si une adresse IP ou un compte
# a ete trouvée et 0 si rien n'a ete trouve
#
sub look_for_address {
	my ($content, $incident_data) = @_;

	my %taddress ;
	for my $addpat (@addresspattern) {
		if($content =~ /[^0-9]($addpat)[^0-9]/m) {
			$taddress{$1} = 1 ;
		}
	}

	my @laddress = keys %taddress;
	my $nbaddr = @laddress;
	# Il ne faut qu'une seule adresse
	if($nbaddr == 1) {
		$incident_data->{ip} = shift @laddress ;
		return 1;
	}
	
	return 0 ;
}

#
# Recupere le login
#
sub get_login_wifi {
	my ($macaddr, $date, $ref) = @_;

	# Normaliser la date
	my $t = date2timet($date);
	my $sqldate = timet2sqldate($t);
	
	# 
	# Recupere le login correspondant a l'adresse mac
	# 
	my $sql="SELECT a.login
			FROM authaccess a, sessionauthaccess s
			WHERE a.idauthaccess = s.idauthaccess
				AND a.mac='$macaddr'
                AND s.fin > '$sqldate'
                AND s.debut < '$sqldate'";
	my $cursor = $dbd_mac->prepare($sql);
	$cursor->execute;

	while ( my ($login) = $cursor->fetchrow ) {
		$ref->{wifi}->{login} = $login;
	}
	$cursor->finish;
}

#
# Localise le reseau et determine le correspondant pour une adresse donnee
#
# Retourne une structure au format suivant :
#	ref {net} =	{
#					name => "Reseau labo Machin"
#					address => "192.168.1.0/24"
#	}
#	ref {grp} = {
#					laboX => ("gerard","marcel","roberta")
#					facY => ("ginette","andre","polo")
#	}
#	ref {corresp} {gerard} = {
#									mail => "gerard@truc.com"
#									cn => "Gerard Smith"
#							}
#
# TODO : passer par un webservice quand il existera
#
sub locate_address {
	my ($ip, $ref) = @_;
	
	#
	# Valeurs par defaut
	#
    $ref->{net} = {};
    $ref->{grp} = {};
    $ref->{corresp} = {};

	# 
	# Recupere le nom et l'adresse du reseau
	# 
	my $sql="SELECT reseau.nom, reseau.adr4 FROM dns.reseau 
			WHERE reseau.adr4 >> '$ip' ";
	my $cursor = $dbd_netmagis->prepare($sql);
	$cursor->execute;
	if (! (($ref->{net}->{name},$ref->{net}->{address}) = $cursor->fetchrow))  {
		# FIXME : message d'erreur approprié & NE PAS QUITTER !
		die("Cannot get network name and address for $ip",$dbd_netmagis->errstr);	
	}
	$cursor->finish;

	# 
	# Recupere le nom du groupe et les logins des correspondants
	# 
	$sql="SELECT groupe.nom, corresp.login
			FROM global.corresp, dns.dr_reseau,
					dns.reseau, global.groupe
			WHERE reseau.adr4 >> '$ip' 
					AND corresp.present = 1
					AND groupe.idgrp = corresp.idgrp 
					AND dr_reseau.idgrp = corresp.idgrp 
					AND dr_reseau.idreseau = reseau.idreseau";
	$cursor = $dbd_netmagis->prepare($sql);
	$cursor->execute;

	my $groupenom = "" ; my $login = "";
	while ( ( $groupenom, $login) = $cursor->fetchrow ) {
		if(! defined($ref->{grp}->{$groupenom})) {
			$ref->{grp}->{$groupenom} = [];
		}
		#
		# Construit la liste des correspondants
		#
		push(@{$ref->{grp}->{$groupenom}}, $login);
	}
	$cursor->finish;

	#
	# Recupere les donnees de chaque correspondant de chaque groupe
	#
	foreach my $groupenom (keys %{$ref->{grp}}) {
		foreach my $login (@ {$ref->{grp}->{$groupenom}} ) {
			if(my $mesg = $ldap->search( base => $ldapbase,
									filter => "(uid=$login)",
									attrs => ["mail","cn"]
									)) {
				foreach my $entry ($mesg->entries) {
					foreach my $att ($entry->attributes) {
						$ref->{corresp}->{$login}->{$att}=$entry->get_value($att);
					}
				}
			} else {
				# FIXME : remonter une erreur & NE PAS QUITTER !
				die("error in ldapsearch for '$login': ".$mesg->error_text);
			}
		}
	}

	# print Dumper($ref);
}

#
# Si l'adresse doit etre translatee, elle est reecrite dans
# $ref->{ip}
#
# TODO: devrait etre un webservice
# TODO: genericiser le code (critere de selection, fonction de translation)
#
sub trans_addr {
	my ($ip, $date, $ref) = shift;

	# Reseaux wifi a translater
	my $wifi = 0;
	my $sql="SELECT * FROM dns.reseau r, dns.communaute c
				WHERE r.adr4 >> '$ip'
					AND c.idcommu=r.idcommu AND c.nom='IP publiques Wifi'";
	my $cursor = $dbd_netmagis->prepare($sql);
	$cursor->execute;
	if ($cursor->fetchrow)  {
		$wifi = 1;
	}
	$cursor->finish;

	if($wifi) {
		if($ip =~ /\.(\d+\.\d+)$/) {
			$ref->{origip} = $ip;
			$ref->{ip} = "172.29.$1";
		}
	} else {

		# 
		# TODO : gerer les reseaux NATés
		# !!!! il manque les port src & dst
		#
	}
}

#
# Converti une chaine de date en time_t
#
sub date2timet {
	my $date = shift;
	
	# si la date est en GMT
	my $tz = "CET";
	if ($date =~ m/GMT$/) {
		$tz = "GMT";
	}

	return parsedate($date, ZONE => $tz);
}

#
# Converti un time_t en date sql
#
sub timet2sqldate {
	my $t = shift;
	
	my $d = Time::Simple->new($t);

	return $d->format("%Y-%m-%d %H:%M:%S");
}

#
# Converti un time_t en date lisible
#
sub timet2readabledate {
	my $t = shift;
	
	my $d = Time::Simple->new($t);

	return $d->format("%d/%m/%Y %H:%M:%S");
}

#
# Recupere l'adresse mac associee a l'adresse ip donnee
# a la date donnee
#
# TODO: utiliser le webservice des qu'il sera ecrit
#
sub get_mac {
	my ($ip, $date, $ref) = @_;

	# Normaliser la date
	my $t = date2timet($date);
	my $sqldate = timet2sqldate($t);

	# Requeter la base
	#	cherche d'abord bail DHCP
	my $sql = "SELECT baildhcp.mac, sessionbaildhcp.debut, sessionbaildhcp.fin
               FROM baildhcp,sessionbaildhcp
               WHERE baildhcp.idbaildhcp = sessionbaildhcp.idbaildhcp
                   AND baildhcp.ip = '$ip'
                   AND sessionbaildhcp.fin > '$sqldate'
                   AND sessionbaildhcp.debut < '$sqldate'";

	# Retourner l'adresse mac
	my $cursor = $dbd_mac->prepare($sql);
	$cursor->execute;

	my $mac = "" ; my $begin = ""; my $end = "";
	while ( ($mac, $begin, $end) = $cursor->fetchrow ) {
		$ref->{mac}->{addr} = $mac;
		$ref->{mac}->{type} = "dhcp";
		$ref->{mac}->{debut} = $begin;
		$ref->{mac}->{end} = $end;
	}
	$cursor->finish;

	#	Si aucun bail dhcp trouve, cherche l'adresse mac dans les sessions mac
	if(! $ref->{mac}->{addr}) {
		my $sql = "SELECT ipmac.mac, sessionipmac.debut, sessionipmac.fin
				   FROM ipmac, sessionipmac
				   WHERE ipmac.idipmac = sessionipmac.idipmac
					   AND ipmac.ip = '$ip'
					   AND sessionipmac.fin > '$sqldate'
					   AND sessionipmac.debut < '$sqldate'";
		# Retourner l'adresse mac
		$cursor = $dbd_mac->prepare($sql);
		$cursor->execute;

		my $mac = "" ; my $begin = ""; my $end = "";
		while ( ($mac, $begin, $end) = $cursor->fetchrow ) {
			$ref->{mac}->{addr} = $mac;
			$ref->{mac}->{type} = "ipmac";
			$ref->{mac}->{debut} = $begin;
			$ref->{mac}->{end} = $end;
		}
		$cursor->finish;
	}

}

######################################################################
#
# Programme principal
#

# Init RT
CleanEnv();
RT::LoadConfig();
RT::Init();

# Connexion a la base netmagis
$dbd_netmagis =  DBI->connect("dbi:Pg:dbname=$dbname_netmagis;host=$dbhost_netmagis",
				$dbuser_netmagis, $dbpass_netmagis) or die ($DBI::errstr);
# Connexion a la base mac
$dbd_mac =  DBI->connect("dbi:Pg:dbname=$dbname_mac;host=$dbhost_mac",
				$dbuser_mac, $dbpass_mac) or die ($DBI::errstr);
# Connexion a l'annuaire
$ldap=Net::LDAP->new("$ldapuri");
my $errmsg = $ldap->bind($ldapbinddn,password=>$ldapbindpw,version=>3);
if($errmsg->code != LDAP_SUCCESS) {
    die("LDAP bind error: ".$errmsg->error);
}

my $mail = "";
# Lit le mail sur l'entree standard
while(<ARGV>) {
    $mail .= $_ ;	
}

handle_message($mail);

exit(0);
