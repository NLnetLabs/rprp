<?php

namespace koenvh\RPKI;


use FG\ASN1\Construct;
use FG\ASN1\OID;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\GeneralizedTime;
use FG\ASN1\Universal\IA5String;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use FG\X509\SAN\IPAddress;
use Ramsey\Uuid\Uuid;

class OpenSSL
{
    private const ROOT_CERTIFICATE_CONFIG = <<<'EOD'
[ req ]
default_md = sha256
default_bits = 2048
encrypt_key = no
distinguished_name = req_dn
x509_extensions = v3_req
string_mask = pkix
prompt = no 

[ req_dn ]
CN = %CN%

[ v3_req ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
basicConstraints=critical, CA:TRUE
keyUsage=critical, keyCertSign, cRLSign
#crlDistributionPoints=URI:rsync://%URL%/repository/%NAME%.crl
subjectInfoAccess=1.3.6.1.5.5.7.48.10;URI:rsync://%URL%/repository/%NAME%.mft,1.3.6.1.5.5.7.48.13;URI:https://%URL%/notification.xml,1.3.6.1.5.5.7.48.5;URI:rsync://%URL%/repository/
certificatePolicies=critical,1.3.6.1.5.5.7.14.2
sbgp-ipAddrBlock=critical,IPv4.0:0.0.0.0/0,IPv6.0:::/0
sbgp-autonomousSysNum=critical,AS.0:0-4294967295
EOD;

    private const SUB_ROOT_CONFIG = <<<'EOD'
[ req ]
default_md = sha256
default_bits = 2048
encrypt_key = no
distinguished_name = req_dn
x509_extensions = v3_req
string_mask = pkix
prompt = no

[ req_dn ]
CN = %CN%

[ v3_req ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
basicConstraints=critical, CA:TRUE
keyUsage=critical, keyCertSign, cRLSign
crlDistributionPoints=URI:rsync://%OLDURL%/repository/%OLDNAME%.crl
authorityInfoAccess=caIssuers;URI:rsync://%OLDURL%/repository/%OLDNAME%.cer
subjectInfoAccess=1.3.6.1.5.5.7.48.10;URI:rsync://%URL%/repository/%NAME%.mft,1.3.6.1.5.5.7.48.13;URI:https://%URL%/notification.xml,1.3.6.1.5.5.7.48.5;URI:rsync://%URL%/repository/
certificatePolicies=critical,1.3.6.1.5.5.7.14.2
sbgp-ipAddrBlock=critical,IPv4.0:0.0.0.0/0,IPv6.0:::/0
sbgp-autonomousSysNum=critical,AS.0:0-4294967295
#1.3.6.1.5.5.7.1.45=critical,DER:02012A
EOD;

    private const SIGNING_CERTIFICATE_CONFIG = <<<'EOD'
[ ca ]
default_ca	= CA_default		# The default ca section

[ CA_default ]
database = /var/cert/index.txt
crlnumber = /var/cert/crl_number
crl_extensions	= crl_ext

default_days	= 365			# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= default		# use public key default MD
preserve	= no			# keep passed DN ordering

[ req ]
default_md = sha256
default_bits = 2048
encrypt_key = no
distinguished_name = req_dn
x509_extensions = v3_req
string_mask = pkix
prompt = no

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ req_dn ]
CN = %CN%

[ v3_req ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
keyUsage=critical,digitalSignature
crlDistributionPoints=URI:rsync://%OLDURL%/repository/%OLDNAME%.crl
authorityInfoAccess=caIssuers;URI:rsync://%OLDURL%/repository/%OLDNAME%.cer
subjectInfoAccess=1.3.6.1.5.5.7.48.11;URI:rsync://%URL%/repository/%NAME%.mft
certificatePolicies=critical,1.3.6.1.5.5.7.14.2

1.3.6.1.5.5.7.1.7=critical,DER:301030060402000105003006040200020500
1.3.6.1.5.5.7.1.8=critical,DER:3004A0020500
EOD;

    private const ROA_CERTIFICATE_CONFIG = <<<'EOD'
[ ca ]
default_ca	= CA_default		# The default ca section

[ CA_default ]
database = /var/cert/index.txt
crlnumber = /var/cert/crl_number
crl_extensions	= crl_ext

default_days	= 365			# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= default		# use public key default MD
preserve	= no			# keep passed DN ordering

[ req ]
default_md = sha256
default_bits = 2048
encrypt_key = no
distinguished_name = req_dn
x509_extensions = v3_req
string_mask = pkix
prompt = no

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ req_dn ]
CN = %CN%

[ v3_req ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
keyUsage=critical,digitalSignature
crlDistributionPoints=URI:rsync://%OLDURL%/repository/%OLDNAME%.crl
authorityInfoAccess=caIssuers;URI:rsync://%OLDURL%/repository/%OLDNAME%.cer
subjectInfoAccess=1.3.6.1.5.5.7.48.11;URI:rsync://%URL%/repository/%NAME%.roa
certificatePolicies=critical,1.3.6.1.5.5.7.14.2

sbgp-ipAddrBlock=critical,IPv4.0:0.0.0.0/0,IPv6.0:2001::/8
EOD;

    private const ASPA_CERTIFICATE_CONFIG = <<<'EOD'
[ ca ]
default_ca	= CA_default		# The default ca section

[ CA_default ]
database = /var/cert/index.txt
crlnumber = /var/cert/crl_number
crl_extensions	= crl_ext

default_days	= 365			# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= default		# use public key default MD
preserve	= no			# keep passed DN ordering

[ req ]
default_md = sha256
default_bits = 2048
encrypt_key = no
distinguished_name = req_dn
x509_extensions = v3_req
string_mask = pkix
prompt = no

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ req_dn ]
CN = %CN%

[ v3_req ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
keyUsage=critical,digitalSignature
crlDistributionPoints=URI:rsync://%OLDURL%/repository/%OLDNAME%.crl
authorityInfoAccess=caIssuers;URI:rsync://%OLDURL%/repository/%OLDNAME%.cer
subjectInfoAccess=1.3.6.1.5.5.7.48.11;URI:rsync://%URL%/repository/%NAME%.asa
certificatePolicies=critical,1.3.6.1.5.5.7.14.2

sbgp-ipAddrBlock=critical,IPv4.0:0.0.0.0/0,IPv6.0:2001::/8
EOD;


    public function generateCertificate($url, &$certificate, &$privateKey, $ca = true, $oldUrl = null, $name = "koenvh", $oldName = "koenvh") {
        if (!$ca && $oldUrl == null) {
            throw new \Exception("Please specify oldUrl");
        }

        if ($ca) {
            $config = self::ROOT_CERTIFICATE_CONFIG;
            $config = str_replace("%CN%", sha1($url), $config);
            $config = str_replace("%URL%", $url, $config);
            $config = str_replace("%NAME%", $name, $config);
        } else {
            $config = self::SUB_ROOT_CONFIG;
            $config = str_replace("%CN%", sha1($url), $config);
            $config = str_replace("%URL%", $url, $config);
            $config = str_replace("%OLDURL%", $oldUrl, $config);
            $config = str_replace("%NAME%", $name, $config);
            $config = str_replace("%OLDNAME%", $oldName, $config);
        }
        $configFile = tempnam(TEMP_FOLDER, "cnf");
        file_put_contents($configFile, $config);

        $certificateFile = tempnam(TEMP_FOLDER, "cer");
        $privateKeyFile = tempnam(TEMP_FOLDER, "key");
        if ($ca) {
            shell_exec("faketime '1 hour ago' openssl req -new -x509 -config $configFile -keyout $privateKeyFile -out $certificateFile -outform DER -days 3580");
        } else {
            $signingFile = tempnam(TEMP_FOLDER, "csr");
            shell_exec("faketime '1 hour ago' openssl req -new -config $configFile -keyout $privateKeyFile -out $signingFile");
            $rootCertificate = $this->retrieveCertificate($oldUrl);
            $rootCertificateFile = tempnam(TEMP_FOLDER, "rca");
            file_put_contents($rootCertificateFile, $rootCertificate);
            $rootPrivateKey = $this->retrievePrivateKey($oldUrl);
            $rootPrivateKeyFile = tempnam(TEMP_FOLDER, "rpv");
            $rootPrivateKeyFilePem = tempnam(TEMP_FOLDER, "rpm");
            file_put_contents($rootPrivateKeyFile, $rootPrivateKey);
            shell_exec("faketime '1 hour ago' openssl x509 -inform DER -in $rootCertificateFile -outform pem -out $rootPrivateKeyFilePem");
            shell_exec("faketime '1 hour ago' openssl x509 -extfile $configFile -extensions v3_req -req -in $signingFile -CA $rootPrivateKeyFilePem -CAkey $rootPrivateKeyFile -CAcreateserial -out $certificateFile -outform DER -days 3580");
        }

        $certificate = file_get_contents($certificateFile);
        $privateKey = file_get_contents($privateKeyFile);
    }

    public function getPublicKey($privateKey) {
        $privateKeyFile = tempnam(TEMP_FOLDER, "key");
        $publickKeyFile = tempnam(TEMP_FOLDER, "pub");
        file_put_contents($privateKeyFile, $privateKey);
        shell_exec("faketime '1 hour ago' openssl rsa -in $privateKeyFile -pubout -outform PEM -out $publickKeyFile");
        return file_get_contents($publickKeyFile);
    }

    public function stripPublicKey($publicKey) {
        $publicKey = str_replace("-----BEGIN PUBLIC KEY-----\n", "", $publicKey);
        $publicKey = str_replace("-----END PUBLIC KEY-----\n", "", $publicKey);
        return $publicKey;
    }

    public function generateManifest($fileList, $privateKey, $url, $oldUrl = null, $name = "koenvh", $oldName = null, &$certificate = null) {
        $fileListAsn1 = [];
        foreach ($fileList as $file) {
            $fileListAsn1[] = new Sequence(
                new IA5String($file["file"]), //file
                new BitString($file["hash"]) //hash
            );
            gc_collect_cycles();
        }

        $manifest = new Sequence(
            new Integer(1337), //manifestNumber
            new GeneralizedTime(date(DATE_ATOM)), //thisUpdate
            new GeneralizedTime("2030-05-09T22:11:12+00:00"), //nextUpdate
            new ObjectIdentifier("2.16.840.1.101.3.4.2.1"), //fileHashAlg
            new Sequence( //fileList
                ...$fileListAsn1
            )
        );

        $binary = $manifest->getBinary();

        $signed = $this->sign($binary, $privateKey, $url, "1.2.840.113549.1.9.16.1.26", $oldUrl, $name, $oldName);
        $certificate = $signed[1];
        return $signed[0];
    }

    public function sign($binary, $privateKey, $url, $contentType, $oldUrl = null, $name = "koenvh", $oldName = null) {
        $binaryFile = tempnam(TEMP_FOLDER, "bin");
        file_put_contents($binaryFile, $binary);

        $manifestFile = tempnam(TEMP_FOLDER, "mft");
        $privateKeyFile = tempnam(TEMP_FOLDER, "key");
        $certificateFile = tempnam(TEMP_FOLDER, "cer");
        $certificateFilePem = tempnam(TEMP_FOLDER, "pem");

        file_put_contents($privateKeyFile, $privateKey);

        if ($contentType == "1.2.840.113549.1.9.16.1.24") {
            $config = self::ROA_CERTIFICATE_CONFIG;
            $config = str_replace("%CN%", Uuid::uuid4(), $config);
        } elseif ($contentType == "1.2.840.113549.1.9.16.1.49") {
            $config = self::ASPA_CERTIFICATE_CONFIG;
            $config = str_replace("%CN%", Uuid::uuid4(), $config);
        } else {
            $config = self::SIGNING_CERTIFICATE_CONFIG;
            $config = str_replace("%CN%", sha1($url), $config);
        }
        $config = str_replace("%URL%", $url, $config);
        $config = str_replace("%OLDURL%", $oldUrl ?? $url, $config);
        $config = str_replace("%NAME%", $name, $config);
        $config = str_replace("%OLDNAME%", $oldName ?? $name, $config);
        $configFile = tempnam(TEMP_FOLDER, "cnf");
        file_put_contents($configFile, $config);

        $signingFile = tempnam(TEMP_FOLDER, "csr");
        shell_exec("faketime '1 hour ago' openssl req -new -config $configFile -keyout $privateKeyFile -out $signingFile");
        $rootCertificate = $this->retrieveCertificate($url);
        $rootCertificateFile = tempnam(TEMP_FOLDER, "rca");
        file_put_contents($rootCertificateFile, $rootCertificate);
        $rootPrivateKey = $this->retrievePrivateKey($url);
        $rootPrivateKeyFile = tempnam(TEMP_FOLDER, "rpv");
        $rootPrivateKeyFilePem = tempnam(TEMP_FOLDER, "rpm");
        file_put_contents($rootPrivateKeyFile, $rootPrivateKey);
        shell_exec("faketime '1 hour ago' openssl x509 -inform DER -in $rootCertificateFile -outform pem -out $rootPrivateKeyFilePem");
        shell_exec("faketime '1 hour ago' openssl x509 -extfile $configFile -extensions v3_req -req -in $signingFile -CA $rootPrivateKeyFilePem -CAkey $rootPrivateKeyFile -CAcreateserial -out $certificateFile -outform DER -days 3580");
        #file_put_contents($certificateFile, $certificate);

        shell_exec("faketime '1 hour ago' openssl x509 -inform DER -in $certificateFile -outform pem -out $certificateFilePem");
        shell_exec("faketime '1 hour ago' openssl cms -binary -in $binaryFile -sign -signer $certificateFilePem -keyid -nodetach -nosmimecap -inkey $privateKeyFile -econtent_type $contentType -outform der -out $manifestFile");

        $cms = file_get_contents($manifestFile);
        $cms = base64_encode($cms);
        //$cms = $this->stripCms($cms);
        return [$cms, file_get_contents($certificateFile)];
    }

    public function generateCrl($certificate, $privateKey, $url, $oldUrl = null, $name = "koenvh", $oldName = null) {
        $privateKeyFile = tempnam(TEMP_FOLDER, "key");
        $certificateFile = tempnam(TEMP_FOLDER, "cer");
        $certificateFilePem = tempnam(TEMP_FOLDER, "pem");
        $certificateRevocationListFile = tempnam(TEMP_FOLDER, "crl");

        file_put_contents($privateKeyFile, $privateKey);
        file_put_contents($certificateFile, $certificate);

        $config = self::SIGNING_CERTIFICATE_CONFIG;
        $config = str_replace("%CN%", sha1($url), $config);
        $config = str_replace("%URL%", $url, $config);
        $config = str_replace("%OLDURL%", $oldUrl ?? $url, $config);
        $config = str_replace("%NAME%", $name, $config);
        $config = str_replace("%OLDNAME%", $oldName ?? $name, $config);
        $configFile = tempnam(TEMP_FOLDER, "cnf");
        file_put_contents($configFile, $config);

        shell_exec("faketime '1 hour ago' openssl x509 -inform DER -in $certificateFile -outform pem -out $certificateFilePem");
        shell_exec("faketime '1 hour ago' openssl ca -config $configFile -gencrl -keyfile $privateKeyFile -cert $certificateFilePem -out $certificateRevocationListFile");

        $certificateRevocationListFileDer = tempnam(TEMP_FOLDER, "der");
        shell_exec("faketime '1 hour ago' openssl crl -inform PEM -in $certificateRevocationListFile -outform DER -out $certificateRevocationListFileDer");

        $crl = file_get_contents($certificateRevocationListFileDer);
        $crl = base64_encode($crl);
        return $crl;
    }

    public function generateBrokenRoa($asn, $ipv4, $ipv6, $privateKey, $url, $oldUrl = null, $name = "koenvh", $oldName = null) {
        $ipAddresses = [];
        $ip4Addresses = [];
        $ip6Addresses = [];

        foreach ($ipv4 as $item) {
            // An IP address with prefix consists of a binary string consisting of N bits that are significant.

            list($address, $prefix) = explode("/", $item, 2);
            $prefix = (int)$prefix;
            $binaryAddress = "";
            foreach (explode(".", $address) as $part) {
                $binaryAddress .= str_pad(decbin($part), 8, "0", STR_PAD_LEFT);
            }

            $binaryAddress = substr($binaryAddress, 0, $prefix);
            $binaryAddress = bin2hex($binaryAddress);

            $unusedBits = 8 - $prefix % 8;
            if ($unusedBits == 8) $unusedBits = 0;

            $ip4Addresses[] = new Sequence(
                new BitString($binaryAddress) // address
            );
        }

        foreach ($ipv6 as $item) {
            if (strpos($item, "::") !== false) {
                throw new \Exception("IPv6 addresses with :: are not supported at the moment");
            }
            list($address, $prefix) = explode("/", $item, 2);
            $prefix = (int)$prefix;
            $binaryAddress = "";
            foreach (explode(":", $address) as $part) {
                $binaryAddress .= str_pad(hex2bin($part), 16, "0", STR_PAD_LEFT);
            }

            $binaryAddress = substr($binaryAddress, 0, $prefix);
            $binaryAddress = bin2hex($binaryAddress);

            $unusedBits = 8 - $prefix % 8;
            if ($unusedBits == 8) $unusedBits = 0;

            $ip6Addresses[] = new Sequence(
                new BitString($binaryAddress) // address
            );
        }

        if (count($ip4Addresses) > 0) {
            $ipAddresses[] = new Sequence(
                new OctetString("0001"), // addressFamily
                new Sequence(...$ip4Addresses) // addresses
            );
        }

        if (count($ip6Addresses) > 0) {
            $ipAddresses[] = new Sequence(
                new OctetString("0002"), // addressFamily
                new Sequence(...$ip6Addresses) // addresses
            );
        }

        $roa = new Sequence(
            new Integer($asn), // asID
            new Sequence( //ipAddrBlocks
                ...$ipAddresses
            )
        );

        $binary = $roa->getBinary();

        return $this->sign($binary, $privateKey, $url, "1.2.840.113549.1.9.16.1.24", $oldUrl, $name, $oldName)[0];
    }

    public function generateRoa($asn, $ipv4, $ipv6, $privateKey, $url, $oldUrl = null, $name = "koenvh", $oldName = null) {
        $ipAddresses = [];
        $ip4Addresses = [];
        $ip6Addresses = [];

        foreach ($ipv4 as $item) {
            // An IP address with prefix consists of a binary string consisting of N bits that are significant.

            list($address, $prefix) = explode("/", $item, 2);
            $prefix = (int)$prefix;
            $binaryAddress = "";
            foreach (explode(".", $address) as $part) {
                $binaryAddress .= str_pad(decbin($part), 8, "0", STR_PAD_LEFT);
            }

            $unusedBits = 8 - $prefix % 8;
            if ($unusedBits == 8) $unusedBits = 0;

            $binaryAddress = substr($binaryAddress, 0, $prefix);
            $binaryAddress .= str_repeat("0", $unusedBits);
            $binaryAddress = base_convert($binaryAddress, 2, 16);

            $ip4Addresses[] = new Sequence(
                new BitString($binaryAddress, $unusedBits), // address
            );
        }

        foreach ($ipv6 as $item) {
            if (strpos($item, "::") !== false) {
                throw new \Exception("IPv6 addresses with :: are not supported at the moment");
            }
            list($address, $prefix) = explode("/", $item, 2);
            $prefix = (int)$prefix;
            $binaryAddress = "";
            foreach (explode(":", $address) as $part) {
                $binaryAddress .= str_pad(base_convert($part, 16, 2), 16, "0", STR_PAD_LEFT);
            }

            $unusedBits = 8 - $prefix % 8;
            if ($unusedBits == 8) $unusedBits = 0;

            $binaryAddress = substr($binaryAddress, 0, $prefix);
            $binaryAddress .= str_repeat("0", $unusedBits);
            $binaryAddress = base_convert($binaryAddress, 2, 16);

            $ip6Addresses[] = new Sequence(
                new BitString($binaryAddress, $unusedBits) // address
            );
        }

        if (count($ip4Addresses) > 0) {
            $ipAddresses[] = new Sequence(
                new OctetString("0001"), // addressFamily
                new Sequence(...$ip4Addresses) // addresses
            );
        }

        if (count($ip6Addresses) > 0) {
            $ipAddresses[] = new Sequence(
                new OctetString("0002"), // addressFamily
                new Sequence(...$ip6Addresses) // addresses
            );
        }

        $roa = new Sequence(
            new Integer($asn), // asID
            new Sequence( //ipAddrBlocks
                ...$ipAddresses
            )
        );

        $binary = $roa->getBinary();

        return $this->sign($binary, $privateKey, $url, "1.2.840.113549.1.9.16.1.24", $oldUrl, $name, $oldName)[0];
    }

    public function generateAspa($customerAsn, $asns, $privateKey, $url, $oldUrl = null, $name = "koenvh", $oldName = null) {
        $providers = [];
        
        foreach ($asns as $asn) {
            switch ($asn["type"]) {
                case "ipv4":
                    $providers[] = new Sequence(
                        new Integer($asn["asn"]),
                        new OctetString("0001")
                    );
                    break;
                case "ipv6":
                    $providers[] = new Sequence(
                        new Integer($asn["asn"]),
                        new OctetString("0002")
                    );
                    break;          
                default:
                    $providers[] = new Sequence(
                        new Integer($asn["asn"])
                    );
                    break;
            }
        }

        $aspa = new Sequence(
            new Integer($customerAsn), // customerASID
            new Sequence( //providers
                ...$providers
            )
        );

        $binary = $aspa->getBinary();

        return $this->sign($binary, $privateKey, $url, "1.2.840.113549.1.9.16.1.49", $oldUrl, $name, $oldName)[0];
    }

    public function generateGhostbusters($fn, $privateKey, $url, $oldUrl = null, $name = "koenvh", $oldName = null) {
        $photo = file_get_contents(__DIR__ . "/../misc/j.txt");

        $gbr = "BEGIN:VCARD\n";
        $gbr .= "VERSION:4.0\n";
        $gbr .= "FN:$fn\n";
        $gbr .= "ORG:Organizational Entity\n";
        $gbr .= "ADR;TYPE=WORK:;;42 Twisty Passage;Deep Cavern;WA;98666;U.S.A.\n";
        $gbr .= "TEL;TYPE=VOICE,TEXT,WORK;VALUE=uri:tel:+1-666-555-1212\n";
        $gbr .= "TEL;TYPE=FAX,WORK;VALUE=uri:tel:+1-666-555-1213\n";
        $gbr .= "EMAIL:human@example.com\n";
        $gbr .= "PHOTO;ENCODING=b;TYPE=image/png:$photo\n";
        $gbr .= "END:VCARD\n";

        $binary = $gbr;

        return $this->sign($binary, $privateKey, $url, "1.2.840.113549.1.9.16.1.35", $oldUrl, $name, $oldName)[0];
    }

    public function stripCrl($crl) {
        $crl = str_replace("-----BEGIN X509 CRL-----\n", "", $crl);
        $crl = str_replace("-----END X509 CRL-----\n", "", $crl);
        $crl = str_replace("\n", "", $crl);
        return $crl;
    }

    public function storePrivateKey($domain, $privateKey, $number = 1) {
        @mkdir(KEYS_FOLDER . "/$domain");
        file_put_contents(KEYS_FOLDER . "/$domain/private_key-$number", $privateKey);
    }

    public function storeCertificate($domain, $certificate, $number = 1) {
        @mkdir(KEYS_FOLDER . "/$domain");
        file_put_contents(KEYS_FOLDER . "/$domain/certificate-$number", $certificate);
    }

    public function storeTal($domain, $tal, $number = 1) {
        @mkdir(KEYS_FOLDER . "/$domain");
        file_put_contents(KEYS_FOLDER . "/$domain/tal-$number", $tal);
    }

    public function storeManifest($domain, $manifest, $number = 1) {
        @mkdir(KEYS_FOLDER . "/$domain");
        file_put_contents(KEYS_FOLDER . "/$domain/manifest-$number", $manifest);
    }

    public function storeCrl($domain, $crl, $number = 1) {
        @mkdir(KEYS_FOLDER . "/$domain");
        file_put_contents(KEYS_FOLDER . "/$domain/crl-$number", $crl);
    }

    public function storeSignedCertificate($domain, $certificate, $number = 1) {
        @mkdir(KEYS_FOLDER . "/$domain");
        file_put_contents(KEYS_FOLDER . "/$domain/signed_certificate-$number", $certificate);
    }

    public function storeRoa($domain, $roa, $number = 1) {
        @mkdir(KEYS_FOLDER . "/$domain");
        file_put_contents(KEYS_FOLDER . "/$domain/roa-$number", $roa);
    }

    public function storeAspa($domain, $aspa, $number = 1) {
        @mkdir(KEYS_FOLDER . "/$domain");
        file_put_contents(KEYS_FOLDER . "/$domain/aspa-$number", $aspa);
    }

    public function storeGhostbusters($domain, $gbr, $number = 1) {
        @mkdir(KEYS_FOLDER . "/$domain");
        file_put_contents(KEYS_FOLDER . "/$domain/gbr-$number", $gbr);
    }

    public function retrievePrivateKey($domain, $number = 1) {
        return file_get_contents(KEYS_FOLDER . "/$domain/private_key-$number");
    }

    public function retrieveCertificate($domain, $number = 1) {
        return file_get_contents(KEYS_FOLDER . "/$domain/certificate-$number");
    }

    public function retrieveTal($domain, $number = 1) {
        return file_get_contents(KEYS_FOLDER . "/$domain/tal-$number");
    }

    public function retrieveManifest($domain, $number = 1) {
        return file_get_contents(KEYS_FOLDER . "/$domain/manifest-$number");
    }

    public function retrieveCrl($domain, $number = 1) {
        return file_get_contents(KEYS_FOLDER . "/$domain/crl-$number");
    }

    public function retrieveSignedCertificate($domain, $number = 1) {
        return file_get_contents(KEYS_FOLDER . "/$domain/signed_certificate-$number");
    }

    public function retrieveRoa($domain, $number = 1) {
        return file_get_contents(KEYS_FOLDER . "/$domain/roa-$number");
    }

    public function retrieveAspa($domain, $number = 1) {
        return file_get_contents(KEYS_FOLDER . "/$domain/aspa-$number");
    }

    public function retrieveGhostbusters($domain, $number = 1) {
        return file_get_contents(KEYS_FOLDER . "/$domain/gbr-$number");
    }
}
