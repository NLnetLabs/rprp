<?php

namespace koenvh\RPKI;

// Code based on:
// https://gist.github.com/magnetikonline/650e30e485c0f91f2f40

use DateTime;
use Psr\Http\Message\ServerRequestInterface;
use Ramsey\Uuid\Uuid;

class DumpHTTPRequest {

    private function execute($targetFile) {
        $data = date(DATE_ATOM) . "\n\n";
        $data .= sprintf(
            "%s %s %s\n\nHTTP headers:\n",
            $_SERVER['REQUEST_METHOD'],
            $_SERVER['REQUEST_URI'],
            $_SERVER['SERVER_PROTOCOL']
        );

        foreach ($this->getHeaderList() as $name => $value) {
            $data .= $name . ': ' . $value . "\n";
        }

        $data .= "\nRequest body:\n";

        file_put_contents(
            $targetFile,
            $data . file_get_contents('php://input') . "\n"
        );
    }

    private function getHeaderList() {
        $headerList = [];
        foreach ($_SERVER as $name => $value) {
            if (preg_match('/^HTTP_/',$name)) {
                // convert HTTP_HEADER_NAME to Header-Name
                $name = strtr(substr($name,5),'_',' ');
                $name = ucwords(strtolower($name));
                $name = strtr($name,' ','-');

                // add to list
                $headerList[$name] = $value;
            }
        }

        return $headerList;
    }

    public function handle(ServerRequestInterface $request, \Closure $next)
    {
        preg_match('/([a-zA-Z]+)[^-]*-([^.]+)\./', $_SERVER['SERVER_NAME'], $matches);
        $code = $matches[1];
        $sessionId = $matches[2];

        @mkdir(REQUESTS_FOLDER . "/$sessionId");
        @mkdir(REQUESTS_FOLDER . "/$sessionId/$code");

        $now = DateTime::createFromFormat('U.u', number_format(microtime(true), 6, '.', ''));
        $filename = $now->format("Ymd-Hisu") . ".txt";

        $this->execute(REQUESTS_FOLDER . "/$sessionId/$code/$filename");

        return $next($request);
    }
}
