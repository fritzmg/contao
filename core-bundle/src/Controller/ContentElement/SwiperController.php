<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Controller\ContentElement;

use Contao\ContentModel;
use Contao\CoreBundle\DependencyInjection\Attribute\AsContentElement;
use Contao\CoreBundle\Twig\FragmentTemplate;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

#[AsContentElement(category: 'miscellaneous', nestedFragments: true)]
class SwiperController extends AbstractContentElementController
{
    protected function getResponse(FragmentTemplate $template, ContentModel $model, Request $request): Response
    {
        $sliderSettings = [
            'speed' => (float) $model->sliderSpeed,
            'offset' => (int) $model->sliderStartSlide,
            'loop' => (bool) $model->sliderContinuous,
        ];

        if ($model->sliderDelay) {
            $swiperSettings['autoplay'] = ['delay' => (float) $model->sliderDelay];
        }

        $template->set('slider_settings', $sliderSettings);

        // Keep old variables for BC
        $template->set('delay', $model->sliderDelay);
        $template->set('speed', $model->sliderSpeed);
        $template->set('offset', $model->sliderStartSlide);
        $template->set('loop', $model->sliderContinuous);

        return $template->getResponse();
    }
}
