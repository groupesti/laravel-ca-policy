<?php

declare(strict_types=1);

namespace CA\Policy\Services\Rules;

use CA\Log\Facades\CaLog;
use CA\Models\CertificateType;
use CA\Policy\Contracts\PolicyRuleInterface;
use CA\Policy\DTOs\PolicyContext;
use CA\Policy\DTOs\PolicyRuleResult;
use CA\Models\PolicySeverity;

class SanRequiredRule implements PolicyRuleInterface
{
    /** @var array<int, string> */
    private readonly array $requiredForTypes;

    /**
     * @param array<string, mixed> $parameters
     */
    public function __construct(array $parameters = [])
    {
        $this->requiredForTypes = (array) ($parameters['required_for_types'] ?? [
            CertificateType::SERVER_TLS,
        ]);
    }

    public function evaluate(PolicyContext $context): PolicyRuleResult
    {
        try {
            $type = $context->type ?? $context->options->type;

            if (!in_array($type->slug, $this->requiredForTypes, true)) {
                return new PolicyRuleResult(
                    passed: true,
                    severity: $this->getSeverity(),
                    message: "SAN not required for certificate type '{$type->slug}'.",
                    rule: $this->getName(),
                );
            }

            $sans = $context->sans ?? $context->options->subjectAlternativeNames;

            if ($sans === null || count($sans) === 0) {
                $message = "Subject Alternative Name is required for '{$type->slug}' certificates per CA/B Forum Baseline Requirements.";

                CaLog::log('policy_violation', 'warning', "Policy violation: {$message}", [
                    'rule' => $this->getName(),
                    'certificate_type' => $type->slug,
                    'ca_id' => $context->ca->id,
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
                'certificate_type' => $type->slug,
                'ca_id' => $context->ca->id,
            ]);

            return new PolicyRuleResult(
                passed: true,
                severity: $this->getSeverity(),
                message: 'Subject Alternative Name is present.',
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
        return 'san_required';
    }

    public function getDescription(): string
    {
        return 'Requires Subject Alternative Name for server certificates per CA/B Forum Baseline Requirements.';
    }

    public function getSeverity(): string
    {
        return PolicySeverity::ERROR;
    }
}
