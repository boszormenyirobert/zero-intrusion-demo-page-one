<?php

namespace App\Logger;

use Symfony\Component\HttpFoundation\RequestStack;

class RequestIdProcessor
{
    private RequestStack $requestStack;

    public function __construct(RequestStack $requestStack)
    {
        $this->requestStack = $requestStack;
    }

    public function __invoke(array $record): array
    {
        $request = $this->requestStack->getCurrentRequest();

        if (!$request) {
            return $record;
        }

        $requestId = $request->headers->get('X-Request-Id');

        if (!$requestId) {
            $requestId = bin2hex(random_bytes(8));
        }

        $record['extra']['request_id'] = $requestId;

        return $record;
    }
}