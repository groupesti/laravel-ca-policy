<?php

declare(strict_types=1);

namespace CA\Policy\Services\Rules;

use CA\Log\Facades\CaLog;
use CA\Policy\Contracts\PolicyRuleInterface;
use CA\Policy\DTOs\PolicyContext;
use CA\Policy\DTOs\PolicyRuleResult;
use CA\Models\PolicySeverity;

class SubjectFieldRule implements PolicyRuleInterface
{
    /** @var array<int, string> */
    private readonly array $requiredFields;

    /** @var array<int, string> */
    private readonly array $forbiddenFields;

    /**
     * @param array<string, mixed> $parameters
     */
    public function __construct(array $parameters = [])
    {
        $this->requiredFields = (array) ($parameters['required_fields'] ?? []);
        $this->forbiddenFields = (array) ($parameters['forbidden_fields'] ?? []);
    }

    public function evaluate(PolicyContext $context): PolicyRuleResult
    {
        try {
            if ($context->subject === null) {
                if (count($this->requiredFields) > 0) {
                    $message = 'Subject DN is required but not provided.';

                    CaLog::log('policy_violation', 'warning', "Policy violation: {$message}", [
                        'rule' => $this->getName(),
                        'ca_id' => $context->ca->id,
                    ]);

                    return new PolicyRuleResult(
                        passed: false,
                        severity: $this->getSeverity(),
                        message: $message,
                        rule: $this->getName(),
                    );
                }

                return new PolicyRuleResult(
                    passed: true,
                    severity: $this->getSeverity(),
                    message: 'No subject DN to validate.',
                    rule: $this->getName(),
                );
            }

            $dnArray = $context->subject->toArray();
            $missing = [];
            $forbidden = [];

            foreach ($this->requiredFields as $field) {
                if (!isset($dnArray[$field]) || $dnArray[$field] === '') {
                    $missing[] = $field;
                }
            }

            foreach ($this->forbiddenFields as $field) {
                if (isset($dnArray[$field]) && $dnArray[$field] !== '') {
                    $forbidden[] = $field;
                }
            }

            if (count($missing) > 0) {
                $message = 'Required subject fields missing: ' . implode(', ', $missing) . '.';

                CaLog::log('policy_violation', 'warning', "Policy violation: {$message}", [
                    'rule' => $this->getName(),
                    'ca_id' => $context->ca->id,
                    'missing_fields' => $missing,
                ]);

                return new PolicyRuleResult(
                    passed: false,
                    severity: $this->getSeverity(),
                    message: $message,
                    rule: $this->getName(),
                );
            }

            if (count($forbidden) > 0) {
                $message = 'Forbidden subject fields present: ' . implode(', ', $forbidden) . '.';

                CaLog::log('policy_violation', 'warning', "Policy violation: {$message}", [
                    'rule' => $this->getName(),
                    'ca_id' => $context->ca->id,
                    'forbidden_fields' => $forbidden,
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
                'ca_id' => $context->ca->id,
            ]);

            return new PolicyRuleResult(
                passed: true,
                severity: $this->getSeverity(),
                message: 'Subject fields meet policy requirements.',
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
        return 'subject_field';
    }

    public function getDescription(): string
    {
        return 'Enforces required and forbidden distinguished name fields.';
    }

    public function getSeverity(): string
    {
        return PolicySeverity::ERROR;
    }
}
