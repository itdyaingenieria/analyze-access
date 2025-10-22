<?php

declare(strict_types=1);

namespace Domain;

interface DetectorInterface
{
    /**
     * Detect suspicious activity patterns in access logs.
     *
     * @param array<int, array{ip:string,endpoint:string,timestamp:int|string,status:int,user_agent:string,response_time?:int}> $logs
     * @param array{max_requests_per_minute:int,max_failed_logins:int,suspicious_endpoints:array<string>,time_window:int,blocked_user_agents:array<string>} $config
     * @return Report
     */
    public function detect(array $logs, array $config): Report;
}
