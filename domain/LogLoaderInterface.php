<?php

declare(strict_types=1);

namespace Domain;

interface LogLoaderInterface
{
    /**
     * Load logs from a source.
     *
     * @param string $source Path to file or resource identifier
     * @return array<int, array{ip:string,endpoint:string,timestamp:int|string,status:int,user_agent:string,response_time?:int}>
     */
    public function load(string $source): array;
}
