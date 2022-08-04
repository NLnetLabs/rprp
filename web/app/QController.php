<?php

namespace koenvh\RPKI;


use Laminas\Diactoros\Response;
use Ramsey\Uuid\Uuid;
use XMLWriter;

class QController
{
    private string $domain = "q.rpki.koenvh.nl";
    private string $sessionId = "23e3c698-2ead-4386-b3be-b04b73f364c1";
    private string $serial = "1337";
    private string $state = "1";

    private const VIRUS_GROWTH = 2;
    private const DUPLICATES = 1; //125_000;

    function __construct() {
        $this->domain = $_SERVER['SERVER_NAME'];
        preg_match('/q([^-]*)-([^.]+)\./', $this->domain, $matches);
        if ($matches[1]) {
            $this->state = $matches[1];
        }
        $this->sessionId = $matches[2];
    }

    function tal() {
        $openSSL = new OpenSSL();

        if (!($content = $openSSL->retrieveTal($this->domain))) {
            $privateKey = null;
            $certificate = null;
            $openSSL->generateCertificate($this->domain, $certificate, $privateKey);
            $publicKey = $openSSL->getPublicKey($privateKey);
            $publicKey = $openSSL->stripPublicKey($publicKey);

            $content = "https://$this->domain/ta/ta.cer\nrsync://$this->domain/ta/ta.cer\n\n$publicKey";
            $openSSL->storePrivateKey($this->domain, $privateKey);
            $openSSL->storeCertificate($this->domain, $certificate);
            $openSSL->storeTal($this->domain, $content);
        }

        return new Response\TextResponse($content, 200, [
            "Content-Type" => "text/plain"
        ]);
    }

    function cer() {
        $openSSL = new OpenSSL();
        return new Response\TextResponse($openSSL->retrieveCertificate($this->domain), 200, [
            "Content-Type" => "application/octet-stream"
        ]);
    }

    function notification() {
        $uniqid = "aspa-aspa-aspa-your-boat";

        $xml = new XMLWriter();
        $xml->openMemory();
        $xml->setIndent(true);
        $xml->startElement("notification");
        $xml->writeAttribute("version", "1");
        $xml->writeAttribute("session_id", $this->sessionId);
        $xml->writeAttribute("serial", $this->serial);
        $xml->writeAttribute("xmlns", "http://www.ripe.net/rpki/rrdp");
        $xml->startElement("snapshot");
        $xml->writeAttribute("uri", "https://$this->domain/$uniqid/snapshot.xml");
        $xml->writeAttribute("hash", $this->snapshot("parent")->getBody()->getContents());
        $xml->endElement();

        $xml->startElement("delta");
        $xml->writeAttribute("serial", $this->serial);
        $xml->writeAttribute("uri", "https://$this->domain/1337/delta.xml");
        $xml->writeAttribute("hash", hash("sha256", $this->delta("1337")->getBody()->getContents()));
        $xml->endElement();

        $xml->endElement();

        return new Response\TextResponse($xml->outputMemory(), 200, [
            "Content-Type" => "text/xml",
            "Last-Modified" => gmdate("D, d M Y H:i:s") . " GMT",
            "Expires" => gmdate("D, d M Y H:i:s") . " GMT",
            "Cache-Control" => "max-age=60"
        ]);
    }

    function snapshot($uniqid) {
        ini_set("memory_limit", "4096M");
        set_time_limit(30 * 60);

        $openSSL = new OpenSSL();

        $firstRun = !$openSSL->retrieveManifest($this->domain, 1);
        if ($firstRun) {
            $initialCrl = $openSSL->generateCrl(
                $openSSL->retrieveCertificate($this->domain, 1),
                $openSSL->retrievePrivateKey($this->domain, 1),
                $this->domain
            );
            $openSSL->storeCrl($this->domain, $initialCrl, 1);

            $fileList = [
                [
                    "file" => "koenvh.crl",
                    "hash" => hash("sha256", base64_decode($openSSL->retrieveCrl($this->domain, 1)))
                ]
            ];

            for ($i = 1; $i < self::VIRUS_GROWTH; $i++) {
                $asns = [];
                for ($l = 0; $l < pow(2, 16); $l++) {
                    $type = null;
                    if ($l % 3 == 0 && $l % 5 == 0) {
                        $type = "all";
                    } elseif ($l % 3 == 0) {
                        $type = "ipv4";
                    } elseif ($l % 5 == 0) {
                        $type = "ipv6";
                    }

                    if ($type) {
                        $asns[] = ["asn" => $l, "type" => $type];
                    }
                }
                $aspa = $openSSL->generateAspa($i, $asns, $openSSL->retrievePrivateKey($this->domain), $this->domain, $this->domain, "koenvh$i-0", "koenvh");
                $openSSL->storeAspa($this->domain, $aspa, $i);

                $hash = hash("sha256", base64_decode($aspa));
                for ($j = 0; $j < self::DUPLICATES; $j++) {
                    $fileList[] = [
                        "file" => "koenvh$i-$j.asa",
                        "hash" => $hash
                    ];
                }
            }

            $initialManifest = $openSSL->generateManifest($fileList, $openSSL->retrievePrivateKey($this->domain, 1), $this->domain, $this->domain, "koenvh", "koenvh");
            $openSSL->storeManifest($this->domain, $initialManifest, 1);
        }

        $xml = new XMLWriter();
        $xml->openMemory();
        $xml->setIndent(true);

        $xml->startElement("snapshot");
        $xml->writeAttribute("version", "1");
        $xml->writeAttribute("session_id", $this->sessionId);
        $xml->writeAttribute("serial", $this->serial);
        $xml->writeAttribute("xmlns", "http://www.ripe.net/rpki/rrdp");

        $xml->startElement("publish");
        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh.cer");
        $xml->writeRaw(base64_encode($openSSL->retrieveCertificate($this->domain, 1)));
        $xml->endElement();

        $xml->startElement("publish");
        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh.crl");
        $xml->writeRaw($openSSL->retrieveCrl($this->domain, 1));
        $xml->endElement();

        $xml->startElement("publish");
        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh.mft");
        $xml->writeRaw($openSSL->retrieveManifest($this->domain, 1));
        $xml->endElement();

        $ctx = hash_init("sha256");
        if ($uniqid == "parent") {
            hash_update($ctx, $xml->outputMemory());
        } else {
            echo $xml->outputMemory();
        }

        for ($i = 1; $i < self::VIRUS_GROWTH; $i++) {
            $rawaspa = $openSSL->retrieveAspa($this->domain, $i);
            for ($j = 0; $j < self::DUPLICATES; $j++) {
                $str = '<publish uri="' . "rsync://$this->domain/repository/koenvh$i-$j.asa" . '">' . $rawaspa . '</publish>' . PHP_EOL;
                if ($uniqid == "parent") {
                    hash_update($ctx, $str);
                } else {
                    echo $str;
                }
//                $xml->startElement("publish");
//                $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh$i-$j.aspa");
//                $xml->writeRaw($rawaspa);
//                $xml->endElement();
                flush();
            }
        }

        $str = "</snapshot>\n";
        if ($uniqid == "parent") {
            hash_update($ctx, $str);
        } else {
            echo $str;
        }
        //$xml->endElement();
        header("Content-Type: text/xml");

        return new Response\TextResponse($uniqid == "parent" ? hash_final($ctx, false) : "", 200, [
            "Content-Type" => "text/xml",
            "Last-Modified" => gmdate("D, d M Y H:i:s") . " GMT",
            "Expires" => gmdate("D, d M Y H:i:s") . " GMT",
            "Cache-Control" => "max-age=60"
        ]);
    }

    function delta($i) {
        return new Response\TextResponse("", 200, [
            "Content-Type" => "text/xml",
            "Last-Modified" => gmdate("D, d M Y H:i:s") . " GMT",
            "Expires" => gmdate("D, d M Y H:i:s") . " GMT",
            "Cache-Control" => "max-age=60"
        ]);
    }
}
