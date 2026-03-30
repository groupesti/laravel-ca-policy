<?php

declare(strict_types=1);

namespace CA\Policy\Services\Rules;

use CA\Log\Facades\CaLog;
use CA\Policy\Contracts\PolicyRuleInterface;
use CA\Policy\DTOs\PolicyContext;
use CA\Policy\DTOs\PolicyRuleResult;
use CA\Models\PolicySeverity;

class CaPathLengthRule implements PolicyRuleInterface
{
    /**
     * @param array<string, mixed> $parameters
     */
    public function __construct(array $parameters = []) {}

    public function evaluate(PolicyContext $context): PolicyRuleResult
    {
        try {
            // Only relevant when issuing a CA certificate.
            if ($context->options->isCa !== true) {
                return new PolicyRuleResult(
                    passed: true,
                    severity: $this->getSeverity(),
                    message: 'Not a CA certificate; path length constraint does not apply.',
                    rule: $this->getName(),
                );
            }

            $ca = $context->ca;
            $caPathLength = $ca->path_length;

            if ($caPathLength === null) {
                return new PolicyRuleResult(
                    passed: true,
                    severity: $this->getSeverity(),
                    message: 'No path length constraint configured on the issuing CA.',
                    rule: $this->getName(),
                );
            }

            $currentDepth = $ca->getChainDepth();

            // The issuing CA allows $caPathLength sub-CAs below it.
            // Current chain depth of the issuing CA + 1 (for the new CA) must not exceed root + pathLength.
            if ($currentDepth >= $caPathLength) {
                $message = "Issuing CA path length constraint ({$caPathLength}) does not allow additional subordinate CAs at chain depth {$currentDepth}.";

                CaLog::log('policy_violation', 'warning', "Policy violation: {$message}", [
                    'rule' => $this->getName(),
                    'ca_id' => $ca->id,
                    'path_length' => $caPathLength,
                    'chain_depth' => $currentDepth,
                ]);

                return new PolicyRuleResult(
                    passed: false,
                    severity: $this->getSeverity(),
                    message: $message,
                    rule: $this->getName(),
                );
            }

            // Check the requested path length of the new CA.
            $requestedPathLength = $context->options->pathLength;

            if ($requestedPathLength !== null && $requestedPathLength >= $caPathLength) {
                $message = "Requested path length ({$requestedPathLength}) must be less than the issuing CA's path length ({$caPathLength}).";

                CaLog::log('policy_violation', 'warning', "Policy violation: {$message}", [
                    'rule' => $this->getName(),
                    'ca_id' => $ca->id,
                    'requested_path_length' => $requestedPathLength,
                    'ca_path_length' => $caPathLength,
                ]);

                return new PolicyRuleResult(
                    passed: false,
                    severity: $this->getSeverity(),
                    message: $message,
                    rule: $this->getName(),
                );
            }

            CaLog::log('policy_evaluation', 'info', "Policy evaluated: {$this->getName()}", [
                'rule' => $this->getName(),
                'ca_id' => $ca->id,
            ]);

            return new PolicyRuleResult(
                passed: true,
                severity: $this->getSeverity(),
                message: 'Path length constraint is satisfied.',
                rule: $this->getName(),
            );
        } catch (\Throwable $e) {
            CaLog::critical($e->getMessage(), [
                'operation' => 'policy_evaluation',
                'exception' => $e::class,
            ]);

            throw $e;
        }
    }

    public function getName(): string
    {
        return 'ca_path_length';
    }

    public function getDescription(): string
    {
        return 'Enforces basicConstraints pathLength down the certificate chain.';
    }

    public function getSeverity(): string
    {
        return PolicySeverity::ERROR;
    }
}
