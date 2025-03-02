<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Messenger;

use Psr\Container\ContainerInterface;
use Symfony\Component\Mailer\Messenger\SendEmailMessage;
use Symfony\Component\Mailer\SentMessage;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Messenger\Exception\RecoverableMessageHandlingException;
use Symfony\Component\Mime\Email;
use Symfony\Component\RateLimiter\LimiterInterface;

#[AsMessageHandler(priority: 100)]
class RateLimitedSendEmailMessageHandler
{
    public function __construct(
        private readonly TransportInterface $transport,
        private readonly ContainerInterface|null $rateLimiterLocator = null,
    ) {
    }

    public function __invoke(SendEmailMessage $message): SentMessage|null
    {
        $email = $message->getMessage();
dd($message);
        if ($email instanceof Email) {
            $transportName = $email->getHeaders()->get('X-Transport')?->getBodyAsString();

            if ($transportName && $this->rateLimiterLocator->has($transportName)) {
                /** @var LimiterInterface */
                $limiter = $this->rateLimiterLocator->get($transportName)->create();
                $limit = $limiter->consume(1);

                if (!$limit->isAccepted()) {
                    throw new RecoverableMessageHandlingException(retryDelay: ($limit->getRetryAfter()->getTimestamp() - time()) * 1000);
                }
            }
        }

        return $this->transport->send($message->getMessage(), $message->getEnvelope());
    }
}
